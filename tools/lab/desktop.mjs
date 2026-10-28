// Launches the debug desktop build for a lab probe and drives it over CDP.
//
// The probes used to start the previous desktop shell and reach into its main process. The app
// is now a Tauri 2 host whose debug build opens WebView2 remote debugging on
// 127.0.0.1 when LOVELYHAWK_DEBUG_PORT is set. Everything here goes through
// that page-level connection plus the two debug-only hooks the host reads in
// place of an operator (crates/lovelyhawk-desktop/src/test_hooks.rs): scripted
// answers for system file dialogs, and a file that receives copied text.
// Nothing in this file is part of the application.
//
//   const app = await startDesktop({ dataRoot, evidence, dialogAnswers: [], clipboard: true });
//   await app.session.evaluate("document.title");
//   app.setDialogAnswers([path.join(evidence, "report.md")]);
//   await app.close();

import { execFileSync } from "node:child_process";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { CdpSession, delay, launchDesktop, listTargets, waitFor } from "../../ui/scripts/cdp.mjs";

export { delay, waitFor };

export const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");

const DEFAULT_SESSION_TIMEOUT_MS = 60_000;
const MAX_RECORDED_ERRORS = 200;

/**
 * The debug desktop executable. Only a debug build honours the archive root,
 * debug port and test hooks, so LOVELYHAWK_DESKTOP_BIN may point at another
 * debug build (a copy, while the usual one is open) but never a release.
 */
export function desktopExecutable() {
  const executable = process.env.LOVELYHAWK_DESKTOP_BIN ??
    path.join(repository, "target", "debug", process.platform === "win32" ? "lovelyhawk.exe" : "lovelyhawk");
  if (!fs.existsSync(executable)) {
    throw new Error(`No desktop build at ${executable}; run \`pnpm desktop:build\` first.`);
  }
  return executable;
}

/** An unused local TCP port, for the WebView2 debugging endpoint. */
export function freePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.on("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      server.close(() => resolve(port));
    });
  });
}

function parseUrl(url) {
  try {
    return new URL(url);
  } catch {
    return null;
  }
}

/** The main window's document: exactly `/` or `/index.html`, no query. */
export function isMainPageUrl(url) {
  const parsed = parseUrl(url);
  return parsed !== null && parsed.hostname === "tauri.localhost" &&
    (parsed.pathname === "/" || parsed.pathname === "/index.html") && parsed.search === "" && parsed.hash === "";
}

/** A child window's document, `terminal.html?window=<kind>`. */
export function isChildPageUrl(url, kind) {
  const parsed = parseUrl(url);
  return parsed !== null && parsed.hostname === "tauri.localhost" &&
    parsed.pathname === "/terminal.html" && parsed.searchParams.get("window") === kind;
}

/**
 * One attached page. `send` and `evaluate` take the same arguments the old
 * per-probe clients did, with a longer default timeout than cdp.mjs because
 * lab targets are slow; `shot(name)` saves into the evidence directory.
 */
export class PageSession {
  #cdp;
  #timeoutMs;
  #evidence;

  constructor(cdp, target, { timeoutMs = DEFAULT_SESSION_TIMEOUT_MS, evidence = null } = {}) {
    this.#cdp = cdp;
    this.#timeoutMs = timeoutMs;
    this.#evidence = evidence;
    this.target = target;
  }

  send(method, params = {}, timeoutMs = this.#timeoutMs) {
    return this.#cdp.send(method, params, timeoutMs);
  }

  evaluate(expression, timeoutMs = this.#timeoutMs) {
    return this.#cdp.evaluate(expression, timeoutMs);
  }

  onEvent(listener) {
    return this.#cdp.onEvent(listener);
  }

  async screenshot(file) {
    const { data } = await this.send("Page.captureScreenshot", { format: "png" });
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, Buffer.from(data, "base64"));
    return file;
  }

  shot(name) {
    if (this.#evidence === null) throw new Error("This page session has no evidence directory.");
    return this.screenshot(path.join(this.#evidence, name));
  }

  close() {
    try {
      this.#cdp.close();
    } catch {
      // Already closed.
    }
  }
}

/**
 * Wraps the page's `fetch` for the Tauri IPC origin and records each command.
 *
 * Tauri defines `__TAURI_INTERNALS__.invoke` as a non-writable property, so it
 * cannot be wrapped the way the earlier probes wrapped a main-process IPC handler.
 * Every invoke on Windows is a POST to `https://ipc.localhost/<command>` made
 * through the global `fetch`, which is the closest equivalent seam: requests
 * pass through unchanged and the response is read from a clone before the page
 * sees it. Only bounded identifiers are kept — never request parameters or
 * response bodies, which can carry credentials.
 */
const HOST_CALL_RECORDER = `(() => {
  if (globalThis.__lovelyhawkLabHostCalls !== undefined) return true;
  const state = { calls: [], order: 0, settled: 0, counts: {} };
  Object.defineProperty(globalThis, '__lovelyhawkLabHostCalls', { value: state });
  const original = globalThis.fetch;
  const text = (value) => typeof value === 'string' ? value.slice(0, 256) : null;
  globalThis.fetch = function (input, init) {
    let url = null;
    try { url = new URL(typeof input === 'string' ? input : input.url); } catch {}
    if (url === null || url.hostname !== 'ipc.localhost') return original.apply(this, arguments);
    let args = null;
    try { args = typeof init?.body === 'string' ? JSON.parse(init.body) : null; } catch {}
    const entry = {
      order: ++state.order, command: decodeURIComponent(url.pathname.slice(1)),
      method: text(args?.method), action: text(args?.params?.action ?? args?.request?.action),
      bindingHandle: text(args?.params?.bindingHandle ?? args?.request?.bindingHandle),
      status: 'pending', responseKind: null, jobHandle: null, settledOrder: null,
    };
    // The log keeps the latest calls; the counts cover every call since recording began.
    const counted = (state.counts[entry.method ?? entry.command] ??= {});
    counted[entry.action ?? ''] = (counted[entry.action ?? ''] ?? 0) + 1;
    if (state.calls.length >= 5000) state.calls.shift();
    state.calls.push(entry);
    return original.apply(this, arguments).then(async (response) => {
      entry.status = response.headers.get('Tauri-Response') === 'ok' ? 'ok' : 'error';
      if ((response.headers.get('content-type') ?? '').startsWith('application/json')) {
        try {
          const body = await response.clone().json();
          entry.responseKind = text(body?.kind);
          entry.jobHandle = text(body?.job?.jobHandle);
        } catch {}
      }
      entry.settledOrder = ++state.settled;
      return response;
    }, (error) => {
      entry.status = 'failed';
      entry.settledOrder = ++state.settled;
      throw error;
    });
  };
  return true;
})()`;

async function attachPage(port, predicate, { label, timeoutMs, sessionTimeoutMs, evidence, errors, onConsoleError, onPageEvent, exclude }) {
  const target = await waitFor(async () => {
    const targets = await listTargets(port);
    return targets.find((candidate) => !exclude.has(candidate.id) && predicate(candidate.url)) ?? null;
  }, { timeoutMs, label });
  const cdp = await CdpSession.connect(target.webSocketDebuggerUrl);
  let phase = "startup";
  if (onPageEvent !== undefined) cdp.onEvent((method, params) => onPageEvent(method, params, target));
  cdp.onEvent((method, params) => {
    let source = null;
    if (method === "Runtime.exceptionThrown") source = "exception";
    else if (method === "Runtime.consoleAPICalled" && params?.type === "error") source = "console";
    else if (method === "Log.entryAdded" && params?.entry?.level === "error") source = "log";
    if (source === null) return;
    const entry = { phase, source, url: target.url, params };
    if (errors.length < MAX_RECORDED_ERRORS) errors.push(entry);
    onConsoleError?.(entry);
  });
  // Enabling Runtime and Log replays what the page already logged, so errors
  // from before the probe attached are still observed (marked "startup").
  await cdp.send("Runtime.enable", {}, sessionTimeoutMs);
  await cdp.send("Log.enable", {}, sessionTimeoutMs);
  phase = "running";
  await cdp.send("Page.enable", {}, sessionTimeoutMs);
  const session = new PageSession(cdp, target, { timeoutMs: sessionTimeoutMs, evidence });
  await waitFor(() => session.evaluate("document.readyState === 'complete'"), { timeoutMs, label: `${label} to finish loading` });
  return session;
}

function validDialogAnswers(answers) {
  return Array.isArray(answers) && answers.every((answer) => answer === null || (typeof answer === "string" && path.isAbsolute(answer)));
}

/**
 * Starts the debug desktop build against `dataRoot` and attaches to its main
 * window.
 *
 * - `dataRoot`: absolute archive root; the app keeps its data in `<dataRoot>/data`.
 * - `port`: debugging port (a free one by default).
 * - `dialogAnswers`: when given (even `[]`), system dialogs consume these
 *   answers in order — an absolute path, or `null` to cancel. With no answer
 *   left the real dialog opens and waits for a person, so a probe must set an
 *   answer before every click that opens one.
 * - `clipboard`: when true, copied text goes to a file instead of the system
 *   clipboard; read it with `readClipboard()`.
 * - `evidence`: directory `session.shot(name)` writes to.
 * - `onConsoleError(entry)`: called for every page error, with
 *   `{ phase: "startup" | "running", source: "exception" | "console" | "log", url, params }`.
 * - `onPageEvent(method, params, target)`: every raw CDP event of every
 *   attached page, subscribed before the domains are enabled.
 * - `env`: further environment for the process.
 */
export async function startDesktop({
  dataRoot,
  port,
  dialogAnswers,
  clipboard = false,
  evidence = null,
  onConsoleError,
  onPageEvent,
  env = {},
  startupTimeoutMs = 60_000,
  sessionTimeoutMs = DEFAULT_SESSION_TIMEOUT_MS,
} = {}) {
  if (typeof dataRoot !== "string" || !path.isAbsolute(dataRoot)) throw new Error("startDesktop needs an absolute data root.");
  if (dialogAnswers !== undefined && !validDialogAnswers(dialogAnswers)) {
    throw new Error("Dialog answers must be absolute paths or null.");
  }
  const executable = desktopExecutable();
  const debugPort = port ?? await freePort();
  // The hook files live outside the data root so the app's own portable data
  // stays exactly what the app wrote.
  const hooks = dialogAnswers !== undefined || clipboard
    ? fs.mkdtempSync(path.join(os.tmpdir(), "lovelyhawk-lab-hooks-"))
    : null;
  const answersFile = dialogAnswers !== undefined ? path.join(hooks, "dialog-answers.json") : null;
  const clipboardFile = clipboard ? path.join(hooks, "clipboard.txt") : null;
  if (answersFile !== null) fs.writeFileSync(answersFile, JSON.stringify(dialogAnswers));
  const extraEnv = { ...env };
  if (answersFile !== null) extraEnv.LOVELYHAWK_TEST_DIALOG_ANSWERS = answersFile;
  if (clipboardFile !== null) extraEnv.LOVELYHAWK_TEST_CLIPBOARD_FILE = clipboardFile;

  const { child, output } = launchDesktop({ executable, archiveRoot: dataRoot, port: debugPort, extraEnv });
  let exitCode = null;
  const exited = new Promise((resolve) => {
    child.once("exit", (code, signal) => {
      exitCode = code ?? signal ?? "unknown";
      resolve(exitCode);
    });
  });
  const errors = [];
  const attached = new Set();
  const sessions = [];
  const attachOptions = { timeoutMs: startupTimeoutMs, sessionTimeoutMs, evidence, errors, onConsoleError, onPageEvent };

  const app = {
    child,
    port: debugPort,
    dataRoot,
    output,
    errors,
    exited,
    session: null,
    hostCallsSince: null,
    get exitCode() { return exitCode; },

    /** The app's own log output (stdout and stderr), most recent last. */
    log(maximum = 8_000) {
      return output.join("").slice(-maximum);
    },

    /** Attaches to a terminal, file-editor or container window opened by the main window. */
    async attachChild(kind, { timeoutMs = 30_000 } = {}) {
      if (!["terminal", "file-editor", "container"].includes(kind)) throw new Error(`Unknown child window kind: ${kind}`);
      const session = await attachPage(debugPort, (url) => isChildPageUrl(url, kind),
        { ...attachOptions, timeoutMs, label: `the ${kind} window`, exclude: attached });
      attached.add(session.target.id);
      sessions.push(session);
      return session;
    },

    /** Replaces the remaining scripted dialog answers. */
    setDialogAnswers(answers) {
      if (answersFile === null) throw new Error("Start the desktop with dialogAnswers to script system dialogs.");
      if (!validDialogAnswers(answers)) throw new Error("Dialog answers must be absolute paths or null.");
      fs.writeFileSync(answersFile, JSON.stringify(answers));
    },

    /** The answers no dialog has consumed yet; the host rewrites the file as it uses them. */
    dialogAnswersLeft() {
      if (answersFile === null) throw new Error("Start the desktop with dialogAnswers to script system dialogs.");
      return JSON.parse(fs.readFileSync(answersFile, "utf8"));
    },

    /** The last text the app copied, or null when it has copied nothing since the last clear. */
    readClipboard() {
      if (clipboardFile === null) throw new Error("Start the desktop with clipboard: true to capture copies.");
      return fs.existsSync(clipboardFile) ? fs.readFileSync(clipboardFile, "utf8") : null;
    },

    clearClipboard() {
      if (clipboardFile === null) throw new Error("Start the desktop with clipboard: true to capture copies.");
      fs.rmSync(clipboardFile, { force: true });
    },

    /** Sizes the main page's viewport; the window minimum is 1080 × 700. */
    async setViewport(width, height) {
      await app.session.send("Emulation.setDeviceMetricsOverride", { width, height, deviceScaleFactor: 1, mobile: false });
    },

    /** Starts recording host commands in the main page; see HOST_CALL_RECORDER. */
    async recordHostCalls() {
      await app.session.send("Page.addScriptToEvaluateOnNewDocument", { source: HOST_CALL_RECORDER });
      await app.session.evaluate(HOST_CALL_RECORDER);
      app.hostCallsSince ??= new Date().toISOString();
    },

    /** The latest recorded host commands (up to 5000), oldest first, optionally one backend method only. */
    async hostCalls({ method } = {}) {
      const calls = await app.session.evaluate(`(() => {
        const state = globalThis.__lovelyhawkLabHostCalls;
        if (state === undefined) return null;
        const method = ${JSON.stringify(method ?? null)};
        return method === null ? state.calls.slice() : state.calls.filter((call) => call.method === method);
      })()`);
      if (calls === null) throw new Error("Host calls are not being recorded in this page.");
      return calls;
    },

    /**
     * The last recorded call for `method` (and `responseKind`, when given):
     * by response order when `settled`, otherwise by request order. Looked up
     * in the page, so polling it stays cheap during long runs.
     */
    async lastHostCall({ method = null, responseKind = null, settled = false } = {}) {
      return app.session.evaluate(`(() => {
        const state = globalThis.__lovelyhawkLabHostCalls;
        if (state === undefined) throw new Error('Host calls are not being recorded in this page');
        const method = ${JSON.stringify(method)}, kind = ${JSON.stringify(responseKind)}, settled = ${settled === true};
        let best = null;
        for (const call of state.calls) {
          if (method !== null && call.method !== method) continue;
          if (kind !== null && call.responseKind !== kind) continue;
          if (settled && call.settledOrder === null) continue;
          if (best === null || (settled ? call.settledOrder > best.settledOrder : call.order > best.order)) best = call;
        }
        return best;
      })()`);
    },

    /** How many times each action of each method (or host command) was requested since recording began. */
    async hostCallCounts() {
      const counts = await app.session.evaluate("globalThis.__lovelyhawkLabHostCalls?.counts ?? null");
      if (counts === null) throw new Error("Host calls are not being recorded in this page.");
      return counts;
    },

    /** Asks the main window to close the way its close button does; the page may still refuse. */
    async requestClose() {
      await app.session.evaluate(`(() => {
        const button = document.querySelector('[data-testid="window-close"]');
        if (button === null) throw new Error('The window close button is missing');
        button.click();
        return true;
      })()`, 5_000);
    },

    /**
     * Closes through the window's own close button so the close handshake
     * runs, waits for the process to exit and WebView2 to let go of the data
     * directory, and falls back to ending the process tree.
     */
    async close({ timeoutMs = 15_000 } = {}) {
      if (exitCode === null && app.session !== null) {
        try { await app.requestClose(); } catch { /* fall through to the kill */ }
      }
      if (exitCode === null) await Promise.race([exited, delay(timeoutMs)]);
      for (const session of sessions) session.close();
      if (exitCode === null) {
        if (process.platform === "win32") {
          try { execFileSync("taskkill.exe", ["/PID", String(child.pid), "/T", "/F"], { windowsHide: true, stdio: "ignore" }); } catch { /* already gone */ }
        } else {
          child.kill();
        }
        await Promise.race([exited, delay(5_000)]);
      }
      await waitForWebViewRelease(dataRoot);
      if (hooks !== null) fs.rmSync(hooks, { recursive: true, force: true });
      return exitCode;
    },
  };

  try {
    app.session = await attachPage(debugPort, isMainPageUrl,
      { ...attachOptions, label: "the main window", exclude: attached });
    attached.add(app.session.target.id);
    sessions.push(app.session);
  } catch (error) {
    await app.close({ timeoutMs: 0 });
    throw new Error(`${error.message}\n${app.log(4_000)}`);
  }
  return app;
}

/**
 * Waits until WebView2 has released its user-data folder after the host
 * exited, so a probe can read or remove the data root. Opening the browser's
 * lockfile fails while a WebView2 process still holds it; nothing is written.
 */
export async function waitForWebViewRelease(dataRoot, timeoutMs = 15_000) {
  const lockfile = path.join(dataRoot, "data", "webview2", "EBWebView", "lockfile");
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (!fs.existsSync(lockfile)) return true;
    try {
      fs.closeSync(fs.openSync(lockfile, "r+"));
      return true;
    } catch {
      await delay(250);
    }
  }
  return false;
}

/**
 * Loads an exported HTML report as an inert document in the main page and
 * returns `inspect(document)`'s JSON value.
 *
 * The earlier probes rendered such a file in a hidden window of the previous
 * shell and took a screenshot. The Tauri host denies new windows and WebView2 offers no
 * second rendering surface, so the file is parsed with the page's own HTML
 * parser instead: structure, text and active-content checks keep their exact
 * meaning, but no layout is computed and no screenshot exists. `inspect` is
 * page-side source text taking the parsed document.
 *
 * A parsed document takes on the page's CSP, so the report's own inline
 * styles (its <style> block, any style attributes) would be refused and
 * logged as console errors the application never caused. They are taken out
 * before parsing. No inspection reads styles; scripts, handlers and images stay
 * exactly as written, and a <style> block's text never parses into elements,
 * so nothing an inspection looks for can hide there.
 */
export async function inspectHtmlFile(session, file, inspect) {
  const html = fs.readFileSync(file, "utf8")
    .replace(/<style\b[^>]*>[\s\S]*?<\/style\s*>/giu, "")
    .replace(/(<[^>]*\s)style(\s*=)/giu, "$1data-probe-style$2");
  return session.evaluate(`(() => {
    const document = new DOMParser().parseFromString(${JSON.stringify(html)}, 'text/html');
    return (${inspect})(document);
  })()`);
}
