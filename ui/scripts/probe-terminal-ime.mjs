// Chinese input in the SSH terminal window, the way an input method delivers
// it: a composition that is updated and then committed, not key presses.
// Checks that the committed text reaches the shell as UTF-8 bytes, that it is
// sent once (no doubled text from both the composition and the commit), that
// an abandoned composition sends nothing, and that the terminal shows the
// text back; and that the grid stays inside its box — composing near the
// right edge used to scroll it sideways, and a grid fitted before the font
// loaded ran past the right and bottom edges. Throwaway data root; the lab
// host is only asked to echo.
//
//   LAB=ubuntu node ui/scripts/probe-terminal-ime.mjs

import { randomUUID } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { labTarget } from "../../tools/lab/lab-target.mjs";
import { Sidecar, backendBinary, connect } from "../../tools/lab/rpc-harness.mjs";
import { attach, delay, launchDesktop, waitFor } from "./cdp.mjs";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const executable = path.join(repositoryRoot, "target", "debug", process.platform === "win32" ? "lovelyhawk.exe" : "lovelyhawk");
const lab = process.env.LAB ?? "ubuntu";
const runRoot = path.join(repositoryRoot, "target", "desktop-debug", `terminal-ime-${randomUUID()}`);
const evidence = path.join(runRoot, "evidence");
const checks = [];
function check(name, ok, detail = null) {
  checks.push({ name, ok: Boolean(ok), detail });
  console.log(`${ok ? "PASS" : "FAIL"} ${name}${detail === null ? "" : ` — ${JSON.stringify(detail).slice(0, 400)}`}`);
}
fs.mkdirSync(evidence, { recursive: true });

const sidecar = new Sidecar(backendBinary(), runRoot);
try {
  const status = await connect(sidecar, { ...labTarget(lab), name: `实验室 ${lab}` });
  if (status?.stage !== "connected") throw new Error(`lab connect failed: ${JSON.stringify(status)}`);
  await sidecar.call("ssh.binding.disconnect", { bindingHandle: status.bindingHandle });
} finally {
  sidecar.close();
}
await delay(500);

const port = 11_800 + Math.floor(Math.random() * 80);
const { child, output } = launchDesktop({ executable, archiveRoot: runRoot, port });
let exitCode = null;
child.once("exit", (code) => { exitCode = code; });
const errors = [];

try {
  const { session: main } = await attach(port, (url) => /^https?:\/\/tauri\.localhost\/(index\.html)?$/u.test(url));
  main.onEvent((method, params) => {
    if (method === "Runtime.exceptionThrown" || (method === "Runtime.consoleAPICalled" && params?.type === "error")) errors.push(`main: ${JSON.stringify(params).slice(0, 1_200)}`);
  });
  await main.send("Runtime.enable");
  await waitFor(() => main.evaluate("document.querySelector('[data-testid=\"sidebar-connect-target\"]') !== null"), { label: "the sidebar" });
  await main.evaluate("document.querySelector('[data-testid=\"sidebar-connect-target\"]').click(), true");
  await waitFor(() => main.evaluate(`(() => { const candidate = document.querySelector('.connection-list-row'); if (!candidate || candidate.disabled) return false; candidate.click(); return true; })()`), { timeoutMs: 15_000, label: "the saved connection" });
  await waitFor(() => main.evaluate(`(() => { const button = [...document.querySelectorAll('.connection-detail button')].find((candidate) => candidate.textContent.trim() === '连接目标' && !candidate.disabled); if (!button) return false; button.click(); return true; })()`), { timeoutMs: 15_000, label: "连接目标" });
  await waitFor(() => main.evaluate("document.querySelector('[data-testid=\"sidebar-open-terminal\"]') !== null && document.querySelector('.connection-manager-backdrop') === null"), { timeoutMs: 90_000, label: "the connection" });
  await main.evaluate("document.querySelector('[data-testid=\"sidebar-open-terminal\"]').click(), true");
  const { session: terminal } = await attach(port, (url) => url.includes("/terminal.html?window=terminal"), 30_000);
  terminal.onEvent((method, params) => {
    if (method === "Runtime.exceptionThrown" || (method === "Runtime.consoleAPICalled" && params?.type === "error")) errors.push(`terminal: ${JSON.stringify(params).slice(0, 1_200)}`);
  });
  await terminal.send("Runtime.enable");
  const lines = () => terminal.evaluate("[...(document.querySelector('.xterm-rows')?.children ?? [])].map((row) => row.textContent).join('\\n')");
  await waitFor(async () => (await lines()).trim().length > 0, { timeoutMs: 45_000, label: "the shell prompt" });
  // The grid, measured against the box it is drawn in: every column and row
  // inside, and nothing but the terminal's own background below the last row.
  const grid = () => terminal.evaluate(`(() => {
    const host = document.querySelector('.terminal-xterm-host');
    const style = getComputedStyle(host);
    const box = host.getBoundingClientRect();
    const inner = {
      right: box.right - parseFloat(style.borderRightWidth) - parseFloat(style.paddingRight),
      bottom: box.bottom - parseFloat(style.borderBottomWidth) - parseFloat(style.paddingBottom),
    };
    const screen = document.querySelector('.xterm-screen').getBoundingClientRect();
    return {
      fits: screen.right <= inner.right + 1 && screen.bottom <= inner.bottom + 1,
      screen: [Math.round(screen.right), Math.round(screen.bottom)],
      inner: [Math.round(inner.right), Math.round(inner.bottom)],
      size: document.querySelector('[data-testid="ssh-window-status"] > span:nth-child(2)')?.textContent ?? null,
      strip: getComputedStyle(document.querySelector('.xterm-viewport')).backgroundColor === style.backgroundColor,
    };
  })()`);
  const atPrompt = await grid();
  check("from the first prompt the whole grid is inside the terminal box", atPrompt.fits, atPrompt);
  check("below the last row is the terminal's own background, not a dark strip", atPrompt.strip, atPrompt);
  await terminal.evaluate("document.querySelector('[data-testid=\"toggle-remote-files\"]').click(), true");
  await delay(800);
  const wide = await grid();
  await terminal.evaluate("document.querySelector('[data-testid=\"toggle-remote-files\"]').click(), true");
  await delay(800);
  const narrow = await grid();
  check("hiding and showing the file pane refits the grid both ways", wide.fits && narrow.fits && wide.size !== narrow.size, { wide, narrow });
  await terminal.evaluate("document.querySelector('.xterm-helper-textarea')?.focus(), true");

  async function keys(text) {
    for (const character of text) {
      await terminal.send("Input.dispatchKeyEvent", { type: "keyDown", key: character, text: character, unmodifiedText: character });
      await terminal.send("Input.dispatchKeyEvent", { type: "keyUp", key: character });
    }
  }
  async function enter() {
    await terminal.send("Input.dispatchKeyEvent", { type: "keyDown", key: "Enter", code: "Enter", windowsVirtualKeyCode: 13, text: "\r" });
    await terminal.send("Input.dispatchKeyEvent", { type: "keyUp", key: "Enter", code: "Enter", windowsVirtualKeyCode: 13 });
  }
  /** What an input method does: compose in steps, then commit. */
  async function compose(steps, committed) {
    for (const text of steps) {
      await terminal.send("Input.imeSetComposition", { text, selectionStart: text.length, selectionEnd: text.length });
      await delay(60);
    }
    await terminal.send("Input.insertText", { text: committed });
    await delay(150);
  }
  /** Runs a line whose output starts with `marker` and returns the rest of that output line. */
  async function outputAfter(marker) {
    return waitFor(async () => {
      const found = (await lines()).split("\n").find((line) => line.startsWith(marker));
      return found === undefined ? null : found.slice(marker.length).trimEnd();
    }, { timeoutMs: 20_000, label: `output ${marker}` }).catch(() => null);
  }

  // 1. A committed composition reaches the shell as UTF-8, once.
  const first = `M${randomUUID().slice(0, 6)}`;
  await keys(`printf '${first}%s\\n' "$(printf '%s' '`);
  await compose(["z", "zh", "zho", "zhon", "zhong", "中"], "中");
  await compose(["w", "we", "wen", "文"], "文");
  await keys(`' | od -An -tx1 | tr -d ' \\n')"`);
  await enter();
  const bytes = await outputAfter(first);
  check("a committed composition reaches the shell as UTF-8 bytes, once", bytes === "e4b8ade69687", bytes);

  // 2. The terminal shows Chinese output back, and the line typed with an input method.
  const second = `S${randomUUID().slice(0, 6)}`;
  await keys(`echo ${second}`);
  await compose(["a", "an", "an'q", "an'qu", "安全"], "安全");
  await compose(["r", "ri", "riz", "rizh", "rizhi", "日志"], "日志");
  await enter();
  const shown = await outputAfter(second);
  check("the terminal shows the composed text in the shell's output", shown === "安全日志", shown);
  const typedLine = (await lines()).split("\n").find((line) => line.includes(`echo ${second}`)) ?? "";
  check("the typed command line shows the composed text where it was typed", typedLine.includes(`echo ${second}安全日志`), typedLine.slice(-60));

  // 3. A composition given up (cleared before commit) sends nothing.
  const third = `C${randomUUID().slice(0, 6)}`;
  await keys(`echo ${third}`);
  await terminal.send("Input.imeSetComposition", { text: "ce", selectionStart: 2, selectionEnd: 2 });
  await delay(60);
  await terminal.send("Input.imeSetComposition", { text: "", selectionStart: 0, selectionEnd: 0 });
  await delay(200);
  await keys("END");
  await enter();
  const abandoned = await outputAfter(third);
  check("a composition given up before commit sends nothing", abandoned === "END", abandoned);

  // 4. Mixed: key presses and a composition in one line, in order.
  const fourth = `X${randomUUID().slice(0, 6)}`;
  await keys(`echo ${fourth}a`);
  await compose(["zhong", "中"], "中");
  await keys("b");
  await compose(["wen", "文"], "文");
  await keys("c");
  await enter();
  const mixed = await outputAfter(fourth);
  check("key presses and compositions arrive in the order they were made", mixed === "a中b文c", mixed);
  // The composition box sits at the cursor; near the right edge it must not
  // scroll the terminal sideways and hide the first columns.
  const shifted = await terminal.evaluate(`(() => {
    const screen = document.querySelector('.xterm-screen');
    const scrolled = [];
    for (let node = screen; node !== null; node = node.parentElement) {
      if (node.scrollLeft !== 0) scrolled.push({ node: node.className || node.tagName, scrollLeft: node.scrollLeft });
    }
    const host = document.querySelector('.ssh-window-terminal')?.getBoundingClientRect();
    const box = screen?.getBoundingClientRect();
    return { scrolled, screenLeft: box?.left ?? null, hostLeft: host?.left ?? null };
  })()`);
  check("composing near the right edge does not scroll the terminal sideways", shifted.scrolled.length === 0 && shifted.screenLeft >= shifted.hostLeft, shifted);
  const afterInput = await grid();
  check("after all that input the grid is still inside the box", afterInput.fits, afterInput);
  await terminal.screenshot(path.join(evidence, "terminal-ime.png"));

  check("no console errors", errors.length === 0, errors.slice(0, 3));
  await main.evaluate("document.querySelector('[data-testid=\"window-close\"]').click(), true");
  await waitFor(() => exitCode !== null, { timeoutMs: 20_000, label: "exit" }).catch(() => undefined);
  check("the app exits cleanly", exitCode === 0, exitCode);
} catch (error) {
  check("probe completed", false, error instanceof Error ? error.message : String(error));
  console.error(output.join("").slice(-3_000));
} finally {
  if (exitCode === null) child.kill();
}

const failed = checks.filter((entry) => !entry.ok);
fs.writeFileSync(path.join(evidence, "report.json"), `${JSON.stringify({
  schema: "lovelyhawk-terminal-ime-probe/v1",
  lab,
  status: failed.length === 0 ? "PASS" : "FAIL",
  generatedAt: new Date().toISOString(),
  checks,
}, null, 2)}\n`);
console.log(`${failed.length === 0 ? "PASS" : "FAIL"}: ${checks.length - failed.length}/${checks.length}; evidence in ${evidence}`);
process.exitCode = failed.length === 0 ? 0 : 1;
