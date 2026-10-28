// A second launch of the same copy brings the running window forward instead
// of opening another or popping a dialog: the debug build is started with its
// own data root, its window minimised, and the same program started again
// against the same data root.
//
// It raises a window on this desktop. Whether that window keeps the front and
// the keyboard afterwards is up to Windows and whoever is using the desktop,
// so this probe records it without asserting it; the packaged manual check
// (docs/PACKAGED_MANUAL_CHECKS.md, B) confirms it with a real double-click.
//   pnpm --filter @lovelyhawk/ui desktop:build
//   node scripts/probe-single-instance.mjs
import { execFileSync, spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { attach, delay, launchDesktop, listTargets, waitFor } from "./cdp.mjs";

const uiRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const repositoryRoot = path.resolve(uiRoot, "..");
const executable = process.env.LOVELYHAWK_DESKTOP_BIN ?? path.join(repositoryRoot, "target", "debug", "lovelyhawk.exe");
const runRoot = path.join(repositoryRoot, "target", "desktop-debug", `single-instance-${randomUUID()}`);
const evidence = path.join(runRoot, "evidence");
const dataDirectory = path.join(runRoot, "data");
const port = 9300 + Math.floor(Math.random() * 500);
const checks = [];
const notRun = [];
function check(name, ok, detail = null) {
  checks.push({ name, ok: Boolean(ok), detail });
  console.log(`${ok ? "PASS" : "FAIL"} ${name}${detail === null ? "" : ` — ${JSON.stringify(detail).slice(0, 600)}`}`);
}

/**
 * The running copy's top-level window as Windows sees it: minimised or not,
 * and whether it is the foreground window. Read from the process, not the
 * page, which does not report itself hidden when minimised.
 */
function nativeWindow(pid) {
  const script = [
    "$ErrorActionPreference = 'Stop'",
    "Add-Type -Namespace Probe -Name User32 -MemberDefinition '[DllImport(\"user32.dll\")] public static extern bool IsIconic(System.IntPtr hWnd); [DllImport(\"user32.dll\")] public static extern System.IntPtr GetForegroundWindow(); [DllImport(\"user32.dll\")] public static extern uint GetWindowThreadProcessId(System.IntPtr hWnd, out uint processId);'",
    "$owner = 0; [void][Probe.User32]::GetWindowThreadProcessId([Probe.User32]::GetForegroundWindow(), [ref]$owner)",
    `$handle = (Get-Process -Id ${pid}).MainWindowHandle`,
    "[pscustomobject]@{ found = ($handle -ne [System.IntPtr]::Zero); minimised = [Probe.User32]::IsIconic($handle); foreground = ([Probe.User32]::GetForegroundWindow() -eq $handle); frontOwner = (Get-Process -Id $owner -ErrorAction SilentlyContinue).ProcessName } | ConvertTo-Json -Compress",
  ].join("; ");
  return JSON.parse(execFileSync("pwsh", ["-NoProfile", "-Command", script], { encoding: "utf8", windowsHide: true, timeout: 30_000 }));
}

/** The same program against the same data root, without a debug port of its own. */
function secondLaunch() {
  const started = Date.now();
  const env = { ...process.env, LOVELYHAWK_ARCHIVE_ROOT: runRoot };
  delete env.LOVELYHAWK_DEBUG_PORT;
  const second = spawn(executable, [], { env, stdio: ["ignore", "pipe", "pipe"], windowsHide: false });
  const output = [];
  second.stdout.on("data", (chunk) => output.push(String(chunk)));
  second.stderr.on("data", (chunk) => output.push(String(chunk)));
  return new Promise((resolve) => {
    // A dialog would hold the process open: more than ten seconds is a failure.
    const timer = setTimeout(() => {
      second.kill();
      resolve({ code: null, milliseconds: Date.now() - started, output: output.join("").slice(-800) });
    }, 10_000);
    second.once("exit", (code) => {
      clearTimeout(timer);
      resolve({ code, milliseconds: Date.now() - started, output: output.join("").slice(-800) });
    });
  });
}

fs.mkdirSync(evidence, { recursive: true });
const { child, output } = launchDesktop({ executable, archiveRoot: runRoot, port });
let exitCode = null;
child.once("exit", (code) => { exitCode = code; });
const errors = [];
try {
  const { session } = await attach(port, (url) => /^https?:\/\/tauri\.localhost\/(index\.html)?$/u.test(url));
  session.onEvent((method, params) => {
    if (method === "Runtime.exceptionThrown" || (method === "Runtime.consoleAPICalled" && params?.type === "error")) {
      errors.push(JSON.stringify(params).slice(0, 1_500));
    }
  });
  await session.send("Runtime.enable");
  await session.send("Page.enable");
  await waitFor(() => session.evaluate("document.querySelector('[data-testid=\"welcome-view\"]') !== null"),
    { label: "the welcome view" });

  await session.evaluate("document.querySelector('[data-testid=\"window-minimize\"]').click(), true");
  const minimised = await waitFor(() => nativeWindow(child.pid).minimised, { timeoutMs: 10_000, intervalMs: 500, label: "minimised" })
    .then(() => true, () => false);
  check("the window is minimised before the second launch", minimised, nativeWindow(child.pid));

  const second = await secondLaunch();
  check("the second launch exits on its own, without waiting on a dialog",
    second.code === 0 && second.milliseconds < 5_000, second);
  const restored = await waitFor(() => { const state = nativeWindow(child.pid); return !state.minimised && state.foreground; },
    { timeoutMs: 5_000, intervalMs: 300, label: "restored" }).then(() => true, () => false);
  check("the running window is restored and brought to the front", restored, nativeWindow(child.pid));
  const samples = [];
  for (let index = 0; index < 8; index += 1) {
    samples.push({ ...nativeWindow(child.pid), page: await session.evaluate("document.hasFocus()"), active: await session.evaluate("document.activeElement?.tagName ?? null") });
    await delay(300);
  }
  notRun.push({ name: "the page keeps the keyboard after the window is raised", observed: samples });
  console.log(`NOT_RUN the page keeps the keyboard — observed ${JSON.stringify(samples.at(-1))}`);
  await session.screenshot(path.join(evidence, "raised.png"));
  check("only one main window exists", (await listTargets(port)).filter((entry) => /tauri\.localhost\/(index\.html)?$/u.test(entry.url)).length === 1);
  check("the request is taken, nothing is left in the data directory",
    !fs.existsSync(path.join(dataDirectory, ".lovelyhawk-show.request")));

  // Asked again while already in front: still one window, still no dialog.
  const again = await secondLaunch();
  check("a launch while the window is in front exits the same way", again.code === 0 && again.milliseconds < 5_000, again);
  check("the running copy logged both requests",
    await waitFor(() => {
      const logs = path.join(dataDirectory, "logs");
      if (!fs.existsSync(logs)) return false;
      const text = fs.readdirSync(logs).map((name) => fs.readFileSync(path.join(logs, name), "utf8")).join("\n");
      return text.split("a second launch asked for the window").length - 1 >= 2;
    }, { timeoutMs: 5_000, label: "the log lines" }).then(() => true, () => false));
  check("no console errors", errors.length === 0, errors.slice(0, 3));

  await session.evaluate("document.querySelector('[data-testid=\"window-close\"]').click(), true");
  await waitFor(() => exitCode !== null, { timeoutMs: 15_000, label: "exit" }).catch(() => undefined);
  check("the app exits cleanly", exitCode === 0, exitCode);
} catch (error) {
  check("scenario completed", false, error instanceof Error ? error.message : String(error));
  console.error(output.join("").slice(-3_000));
} finally {
  if (exitCode === null) child.kill();
}
const failed = checks.filter((entry) => !entry.ok);
fs.writeFileSync(path.join(evidence, "report.json"), `${JSON.stringify({ status: failed.length === 0 ? "PASS" : "FAIL", checks, notRun }, null, 2)}\n`);
console.log(`${failed.length === 0 ? "PASS" : "FAIL"}: ${checks.length - failed.length}/${checks.length}; evidence in ${evidence}`);
process.exitCode = failed.length === 0 ? 0 : 1;
