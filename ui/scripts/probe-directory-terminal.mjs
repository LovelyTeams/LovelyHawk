// "在这里打开终端" from the SSH window's file pane, against a real lab host:
// a terminal window that starts in the chosen folder (a folder whose name is
// shell syntax included), opened from a folder's menu and from the toolbar,
// each request a new shell like a new tab, no file pane of its own, and the
// SSH window's file pane still working beside it; a folder removed after it
// was listed and a fifth terminal on the host each leave a window that says
// why, and asking again after closing one opens a fresh window. Everything
// happens in a fresh directory under /tmp on the lab host, removed at the end.
//
//   LAB=ubuntu node ui/scripts/probe-directory-terminal.mjs

import { execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { labTarget } from "../../tools/lab/lab-target.mjs";
import { Sidecar, backendBinary, connect } from "../../tools/lab/rpc-harness.mjs";
import { CdpSession, attach, delay, launchDesktop, listTargets, waitFor } from "./cdp.mjs";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const executable = path.join(repositoryRoot, "target", "debug", process.platform === "win32" ? "lovelyhawk.exe" : "lovelyhawk");
const lab = process.env.LAB ?? "ubuntu";
const container = `lab-${lab}`;
const id = randomUUID().slice(0, 8);
const base = `lh-dirterm-${id}`;
const remoteDirectory = `/tmp/${base}`;
// Shell syntax in a folder name: the shell must be started in it, not run it.
const hostile = "it's a dir; touch PWNED";
const runRoot = path.join(repositoryRoot, "target", "desktop-debug", `directory-terminal-${randomUUID()}`);
const evidence = path.join(runRoot, "evidence");
const checks = [];
function check(name, ok, detail = null) {
  checks.push({ name, ok: Boolean(ok), detail });
  console.log(`${ok ? "PASS" : "FAIL"} ${name}${detail === null ? "" : ` — ${JSON.stringify(detail).slice(0, 400)}`}`);
}
fs.mkdirSync(evidence, { recursive: true });
function docker(...args) {
  // -e runs docker directly; "--" would hand the line to a shell first.
  return execFileSync("wsl.exe", ["-d", "Ubuntu", "-u", "root", "-e", "docker", ...args], { encoding: "utf8" });
}
const onHost = (script) => docker("exec", container, "sh", "-c", script);
docker("exec", "-e", `LH_HOSTILE=${hostile}`, container, "sh", "-c",
  `mkdir -p ${remoteDirectory}/plain ${remoteDirectory}/gone ${remoteDirectory}/extra ${remoteDirectory}/fifth` +
    ` && mkdir -p "${remoteDirectory}/$LH_HOSTILE" && printf 'notes\\n' > ${remoteDirectory}/notes.txt`);

const sidecar = new Sidecar(backendBinary(), runRoot);
try {
  const status = await connect(sidecar, { ...labTarget(lab), name: `实验室 ${lab}` });
  if (status?.stage !== "connected") throw new Error(`lab connect failed: ${JSON.stringify(status)}`);
  await sidecar.call("ssh.binding.disconnect", { bindingHandle: status.bindingHandle });
} finally {
  sidecar.close();
}
await delay(500);

const port = 11_700 + Math.floor(Math.random() * 80);
const { child, output } = launchDesktop({ executable, archiveRoot: runRoot, port });
let exitCode = null;
child.once("exit", (code) => { exitCode = code; });
const errors = [];
function watch(session, name) {
  session.onEvent((method, params) => {
    if (method === "Runtime.exceptionThrown" || (method === "Runtime.consoleAPICalled" && params?.type === "error")) {
      errors.push(`${name}: ${JSON.stringify(params).slice(0, 1_200)}`);
    }
  });
}
const row = (name) => `[...document.querySelectorAll('section[aria-label="远程文件"] .sftp-browser-row')].find((candidate) => candidate.querySelector('.sftp-browser-row-label')?.textContent === ${JSON.stringify(name)})`;
/** Opens a row's menu, reads it once it has rendered, and closes it again. */
async function menuOf(session, name) {
  await session.evaluate(`(() => {
    const candidate = ${row(name)};
    if (!candidate) return false;
    const box = candidate.getBoundingClientRect();
    candidate.dispatchEvent(new MouseEvent('contextmenu', { bubbles: true, cancelable: true, clientX: box.left + 20, clientY: box.top + 5 }));
    return true;
  })()`);
  const items = await waitFor(() => session.evaluate(`(() => {
    const items = [...document.querySelectorAll('[role="menuitem"]')].map((entry) => entry.textContent.trim());
    return items.length > 0 ? items : null;
  })()`), { timeoutMs: 10_000, label: `the menu of ${name}` }).catch(() => null);
  await session.evaluate("window.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true })), true");
  await waitFor(() => session.evaluate("document.querySelector('[role=\"menuitem\"]') === null"), { timeoutMs: 5_000, label: "the menu to close" }).catch(() => undefined);
  return items;
}
const location = (session) => session.evaluate("document.querySelector('section[aria-label=\"远程文件\"] .sftp-browser-path-value')?.textContent ?? null");
/** Opens a folder in the pane and waits until the path bar shows it. */
async function browse(session, name) {
  await waitFor(() => session.evaluate(`(() => { const candidate = ${row(name)}; if (!candidate || candidate.disabled) return false; candidate.dispatchEvent(new MouseEvent('dblclick', { bubbles: true })); return true; })()`), { timeoutMs: 30_000, label: `the ${name} row` });
  return waitFor(async () => (await location(session)) === name ? name : null, { timeoutMs: 30_000, label: `the ${name} listing` }).catch(() => null);
}
const chooseFromMenu = (name, label) => `(() => {
  const candidate = ${row(name)};
  if (!candidate) return false;
  const box = candidate.getBoundingClientRect();
  candidate.dispatchEvent(new MouseEvent('contextmenu', { bubbles: true, cancelable: true, clientX: box.left + 20, clientY: box.top + 5 }));
  const item = [...document.querySelectorAll('[role="menuitem"]')].find((entry) => entry.textContent.trim() === ${JSON.stringify(label)});
  if (!item || item.disabled) return false;
  item.click();
  return true;
})()`;
const folderWindows = async () => (await listTargets(port)).filter((entry) => entry.url.includes("/terminal.html?window=directory"));
const attached = new Map();
/** The folder window that appeared since `before`, attached and watched. */
async function newFolderWindow(before, label) {
  const known = new Set(before.map((entry) => entry.id));
  const entry = await waitFor(async () => (await folderWindows()).find((candidate) => !known.has(candidate.id)) ?? null,
    { timeoutMs: 30_000, label });
  const session = await CdpSession.connect(entry.webSocketDebuggerUrl);
  watch(session, label);
  await session.send("Runtime.enable");
  attached.set(entry.id, session);
  return { id: entry.id, session };
}
async function typeLine(session, text) {
  await session.evaluate("document.querySelector('.xterm-helper-textarea')?.focus(), true");
  for (const character of text) {
    await session.send("Input.dispatchKeyEvent", { type: "keyDown", key: character, text: character, unmodifiedText: character });
    await session.send("Input.dispatchKeyEvent", { type: "keyUp", key: character });
  }
  await session.send("Input.dispatchKeyEvent", { type: "keyDown", key: "Enter", code: "Enter", windowsVirtualKeyCode: 13, text: "\r" });
  await session.send("Input.dispatchKeyEvent", { type: "keyUp", key: "Enter", code: "Enter", windowsVirtualKeyCode: 13 });
}
// One line per row: a long line wraps onto the next row with no separator.
const screen = (session) => session.evaluate("[...(document.querySelector('.xterm-rows')?.children ?? [])].map((rowElement) => rowElement.textContent).join('\\n')");
/** Runs `pwd` between two markers and reads back what it printed. */
async function workingDirectory(session) {
  const marker = `D${randomUUID().slice(0, 6)}`;
  await waitFor(async () => (await screen(session)).trim().length > 0, { timeoutMs: 45_000, label: "the folder shell" });
  await typeLine(session, `echo ${marker}"$(pwd)"${marker}`);
  return waitFor(async () => {
    // The printed line starts with the marker; the echoed command line does not.
    // Rows of one wrapped line are joined back before looking.
    const lines = (await screen(session)).split("\n");
    for (let index = 0; index < lines.length; index += 1) {
      if (!lines[index].startsWith(`${marker}/`)) continue;
      let joined = lines[index];
      for (let next = index + 1; !joined.trimEnd().endsWith(marker) && next < lines.length; next += 1) joined += lines[next];
      const found = joined.trimEnd();
      if (found.endsWith(marker)) return found.slice(marker.length, -marker.length);
    }
    return null;
  }, { timeoutMs: 20_000, label: "pwd" }).catch(() => null);
}
const windowState = (session) => session.evaluate(`({
  label: document.documentElement.dataset.targetLabel ?? '',
  chip: document.querySelector('.ssh-window-chip.is-quiet')?.textContent ?? null,
  toggle: document.querySelector('[data-testid="toggle-remote-files"]') !== null,
  pane: document.querySelector('.ssh-window-files') !== null,
  note: document.querySelector('[data-testid="terminal-files-note"]')?.textContent ?? null,
  alert: document.querySelector('.terminal-error')?.textContent ?? null,
  session: document.querySelector('[data-testid="ssh-window-session"]')?.textContent ?? null,
  time: document.querySelector('[data-testid="ssh-window-status"] > span')?.textContent ?? null,
})`);

try {
  const { session: main } = await attach(port, (url) => /^https?:\/\/tauri\.localhost\/(index\.html)?$/u.test(url));
  watch(main, "main");
  await main.send("Runtime.enable");
  await waitFor(() => main.evaluate("document.querySelector('[data-testid=\"sidebar-connect-target\"]') !== null"), { label: "the sidebar" });
  await main.evaluate("document.querySelector('[data-testid=\"sidebar-connect-target\"]').click(), true");
  await waitFor(() => main.evaluate(`(() => { const candidate = document.querySelector('.connection-list-row'); if (!candidate || candidate.disabled) return false; candidate.click(); return true; })()`), { timeoutMs: 15_000, label: "the saved connection" });
  await waitFor(() => main.evaluate(`(() => { const button = [...document.querySelectorAll('.connection-detail button')].find((candidate) => candidate.textContent.trim() === '连接目标' && !candidate.disabled); if (!button) return false; button.click(); return true; })()`), { timeoutMs: 15_000, label: "连接目标" });
  await waitFor(() => main.evaluate("document.querySelector('[data-testid=\"sidebar-open-terminal\"]') !== null && document.querySelector('.connection-manager-backdrop') === null"), { timeoutMs: 90_000, label: "the connection" });
  await main.evaluate("document.querySelector('[data-testid=\"sidebar-open-terminal\"]').click(), true");
  const { session: terminal } = await attach(port, (url) => url.includes("/terminal.html?window=terminal"), 30_000);
  watch(terminal, "ssh window");
  await terminal.send("Runtime.enable");
  await waitFor(() => terminal.evaluate("document.querySelector('[data-testid=\"toggle-remote-files\"]')?.getAttribute('aria-expanded') === 'true'"), { timeoutMs: 30_000, label: "the file panel" });
  for (const name of ["tmp", base]) await browse(terminal, name);
  await waitFor(() => terminal.evaluate(`${row(hostile)} !== undefined && ${row("notes.txt")} !== undefined`), { timeoutMs: 30_000, label: "the probe folders" });

  // Offered on folders and on the folder being viewed; not on a file.
  const folderMenu = await menuOf(terminal, "plain");
  const fileMenu = await menuOf(terminal, "notes.txt");
  const toolbar = await terminal.evaluate("(() => { const button = document.querySelector('[data-testid=\"sftp-terminal-here\"]'); return button === null ? null : { text: button.textContent.trim(), disabled: button.disabled, title: button.title }; })()");
  check("a folder's menu offers 在这里打开终端, a file's does not, and the toolbar has it for the folder on screen",
    folderMenu?.includes("在这里打开终端") && !fileMenu?.includes("在这里打开终端") && toolbar?.text === "在这里打开终端" && toolbar.disabled === false,
    { folderMenu, fileMenu, toolbar });

  // A folder named with shell syntax: the shell starts in it and runs none of it.
  let before = await folderWindows();
  await waitFor(() => terminal.evaluate(chooseFromMenu(hostile, "在这里打开终端")), { timeoutMs: 20_000, label: "在这里打开终端 on the hostile folder" });
  const first = await newFolderWindow(before, "the hostile folder's window");
  const firstPwd = await workingDirectory(first.session);
  check("the new window's shell starts in that folder", firstPwd === `${remoteDirectory}/${hostile}`, firstPwd);
  check("nothing in the folder name ran", onHost(`find ${remoteDirectory} -name PWNED | wc -l`).trim() === "0" && onHost("ls / /root | grep -c PWNED || true").trim() === "0");
  const firstState = await windowState(first.session);
  check("the folder window names the target and the folder, and has no file pane of its own",
    firstState.label.endsWith(`· 文件夹 ${hostile}`) && firstState.chip === "SSH · 文件夹" && !firstState.toggle && !firstState.pane &&
      firstState.note === "主机文件在 SSH 终端窗口的文件管理中", firstState);
  check("a live folder shell says 已连接 and counts its session time", firstState.session === "已连接" && /^会话时间 \d\d:\d\d:\d\d$/u.test(firstState.time ?? ""), firstState);
  await first.session.screenshot(path.join(evidence, "folder-terminal.png"));

  // The SSH window's own pane keeps working beside it.
  const inPlain = await browse(terminal, "plain");
  await waitFor(() => terminal.evaluate(`(() => { const button = document.querySelector('section[aria-label="远程文件"] button[aria-label="上一级"]'); if (!button || button.disabled) return false; button.click(); return true; })()`), { timeoutMs: 20_000, label: "上一级" });
  const backAgain = await waitFor(async () => (await location(terminal)) === base && await terminal.evaluate(`${row(hostile)} !== undefined`) ? true : null, { timeoutMs: 20_000, label: "the probe folder again" }).catch(() => null);
  const paneError = await terminal.evaluate("document.querySelector('[data-testid=\"sftp-window-error\"], .sftp-browser-page [role=\"alert\"]')?.textContent ?? null");
  check("the SSH window's file pane still lists folders after the folder window opened", inPlain === "plain" && backAgain === true && paneError === null, { inPlain, backAgain, paneError });

  // The same folder again is a second shell there, like a new tab; closing it
  // leaves the first one running.
  before = await folderWindows();
  await waitFor(() => terminal.evaluate(chooseFromMenu(hostile, "在这里打开终端")), { timeoutMs: 20_000, label: "在这里打开终端 again" });
  const again = await newFolderWindow(before, "the same folder's second window");
  const againPwd = await workingDirectory(again.session);
  await again.session.evaluate("document.querySelector('[data-testid=\"window-close\"]').click(), true");
  await waitFor(async () => !(await folderWindows()).some((entry) => entry.id === again.id), { timeoutMs: 15_000, label: "the second window to close" }).catch(() => undefined);
  const firstStillThere = (await folderWindows()).some((entry) => entry.id === first.id);
  check("asking for the same folder again opens a second shell there, and closing it leaves the first",
    againPwd === `${remoteDirectory}/${hostile}` && again.id !== first.id && firstStillThere, { againPwd, firstStillThere });

  // The toolbar button opens one in the folder being viewed.
  before = await folderWindows();
  await terminal.evaluate("document.querySelector('[data-testid=\"sftp-terminal-here\"]').click(), true");
  const second = await newFolderWindow(before, "the current folder's window");
  check("the toolbar opens a shell in the folder on screen", (await workingDirectory(second.session)) === remoteDirectory);
  // Leaving the shell ends the session, and its window goes with it, as every
  // terminal window does; the terminal it held is released on the host.
  await typeLine(second.session, "exit");
  const closedOnExit = await waitFor(async () => !(await folderWindows()).some((entry) => entry.id === second.id) ? true : null,
    { timeoutMs: 20_000, label: "the window to close after exit" }).catch(() => false);
  check("typing exit ends the folder shell and closes its window", closedOnExit === true);

  // A folder removed after it was listed: the window stays and says so.
  onHost(`rmdir ${remoteDirectory}/gone`);
  before = await folderWindows();
  await waitFor(() => terminal.evaluate(chooseFromMenu("gone", "在这里打开终端")), { timeoutMs: 20_000, label: "在这里打开终端 on gone" });
  const gone = await newFolderWindow(before, "the removed folder's window");
  const goneAlert = await waitFor(async () => (await windowState(gone.session)).alert, { timeoutMs: 45_000, label: "the removed folder's reason" }).catch(() => null);
  check("a folder removed since it was listed leaves a window that says the shell could not start there",
    goneAlert?.startsWith("没能在这个文件夹里打开终端。") === true && !/[A-Za-z]{4,}|\(/u.test(goneAlert), goneAlert);
  const goneState = await windowState(gone.session);
  check("that window does not claim a connection or a session time", goneState.session === "未连接" && goneState.time === "会话时间 —", goneState);
  await gone.session.screenshot(path.join(evidence, "folder-gone.png"));

  // Four terminals per host: the SSH window and the hostile folder's are open;
  // two more fit, a fifth does not.
  const opened = [];
  for (const name of ["plain", "extra"]) {
    before = await folderWindows();
    await waitFor(() => terminal.evaluate(chooseFromMenu(name, "在这里打开终端")), { timeoutMs: 20_000, label: `在这里打开终端 on ${name}` });
    const window = await newFolderWindow(before, `the ${name} terminal`);
    opened.push({ name, pwd: await workingDirectory(window.session) });
  }
  check("the third and fourth terminals on the host open", opened.every(({ name, pwd }) => pwd === `${remoteDirectory}/${name}`), opened);
  before = await folderWindows();
  await waitFor(() => terminal.evaluate(chooseFromMenu("fifth", "在这里打开终端")), { timeoutMs: 20_000, label: "在这里打开终端 on fifth" });
  const fifth = await newFolderWindow(before, "the fifth terminal");
  const crowded = await waitFor(async () => (await windowState(fifth.session)).alert, { timeoutMs: 45_000, label: "the capacity reason" }).catch(() => null);
  check("a fifth says the host has too many terminals open and to close one", crowded === "这台主机上打开的终端已经太多（最多 4 个）。关掉一个再试。", crowded);

  // Close one, ask again: a fresh window that works, beside the one that said why it could not.
  await first.session.evaluate("document.querySelector('[data-testid=\"window-close\"]').click(), true");
  await waitFor(async () => !(await folderWindows()).some((entry) => entry.id === first.id), { timeoutMs: 15_000, label: "the first folder window to close" });
  await delay(1_000);
  before = await folderWindows();
  await waitFor(() => terminal.evaluate(chooseFromMenu("fifth", "在这里打开终端")), { timeoutMs: 20_000, label: "在这里打开终端 on fifth again" });
  const retry = await newFolderWindow(before, "the retried terminal");
  const retryPwd = await workingDirectory(retry.session);
  const failedStays = (await windowState(fifth.session)).alert;
  check("after closing one, asking again opens a fresh window that works, and the refused one still says why",
    retry.id !== fifth.id && retryPwd === `${remoteDirectory}/fifth` && failedStays === crowded, { retryPwd, failedStays });
  await terminal.screenshot(path.join(evidence, "ssh-window.png"));

  check("no console errors", errors.length === 0, errors.slice(0, 3));
  await main.evaluate("document.querySelector('[data-testid=\"window-close\"]').click(), true");
  await waitFor(() => exitCode !== null, { timeoutMs: 20_000, label: "exit" }).catch(() => undefined);
  check("the app exits cleanly and closes every folder window with it", exitCode === 0, exitCode);
} catch (error) {
  check("probe completed", false, error instanceof Error ? error.message : String(error));
  console.error(output.join("").slice(-3_000));
} finally {
  if (exitCode === null) child.kill();
  try {
    onHost(`rm -rf ${remoteDirectory}`);
  } catch {
    // Left for the next run's operator to see; it is a throwaway folder under /tmp.
  }
}

const failed = checks.filter((entry) => !entry.ok);
fs.writeFileSync(path.join(evidence, "report.json"), `${JSON.stringify({
  schema: "lovelyhawk-directory-terminal-probe/v1",
  lab,
  status: failed.length === 0 ? "PASS" : "FAIL",
  generatedAt: new Date().toISOString(),
  checks,
}, null, 2)}\n`);
console.log(`${failed.length === 0 ? "PASS" : "FAIL"}: ${checks.length - failed.length}/${checks.length}; evidence in ${evidence}`);
process.exitCode = failed.length === 0 ? 0 : 1;
