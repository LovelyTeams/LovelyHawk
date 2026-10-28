// Minimal Chrome DevTools Protocol client for the desktop app's WebView2.
//
// The debug build opens a remote-debugging port only when LOVELYHAWK_DEBUG_PORT
// is set; this talks to it over the WebSocket Node ships with. Nothing here is
// part of the application itself.

import { spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

export function delay(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

export async function waitFor(check, { timeoutMs = 30_000, intervalMs = 200, label = "condition" } = {}) {
  const deadline = Date.now() + timeoutMs;
  let lastError = null;
  while (Date.now() < deadline) {
    try {
      const value = await check();
      if (value) return value;
    } catch (error) {
      lastError = error;
    }
    await delay(intervalMs);
  }
  throw new Error(`Timed out waiting for ${label}${lastError ? `: ${lastError.message}` : ""}`);
}

/** Lists the page targets the WebView2 browser process exposes. */
export async function listTargets(port) {
  const response = await fetch(`http://127.0.0.1:${port}/json/list`);
  if (!response.ok) throw new Error(`CDP target list answered ${response.status}`);
  return (await response.json()).filter((target) => target.type === "page");
}

export class CdpSession {
  #socket;
  #nextId = 1;
  #pending = new Map();
  #listeners = new Set();

  static async connect(webSocketDebuggerUrl) {
    const session = new CdpSession();
    session.#socket = new WebSocket(webSocketDebuggerUrl);
    await new Promise((resolve, reject) => {
      session.#socket.addEventListener("open", resolve, { once: true });
      session.#socket.addEventListener("error", () => reject(new Error("CDP socket failed to open")), { once: true });
    });
    session.#socket.addEventListener("message", (event) => session.#receive(String(event.data)));
    session.#socket.addEventListener("close", () => {
      for (const { reject } of session.#pending.values()) reject(new Error("CDP socket closed"));
      session.#pending.clear();
    });
    return session;
  }

  #receive(text) {
    const message = JSON.parse(text);
    if (message.id !== undefined) {
      const pending = this.#pending.get(message.id);
      if (pending === undefined) return;
      this.#pending.delete(message.id);
      clearTimeout(pending.timer);
      if (message.error) pending.reject(new Error(`${message.error.message} (${message.error.code})`));
      else pending.resolve(message.result);
      return;
    }
    for (const listener of this.#listeners) listener(message.method, message.params);
  }

  onEvent(listener) {
    this.#listeners.add(listener);
    return () => this.#listeners.delete(listener);
  }

  send(method, params = {}, timeoutMs = 10_000) {
    const id = this.#nextId++;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.#pending.delete(id);
        reject(new Error(`CDP ${method} timed out`));
      }, timeoutMs);
      this.#pending.set(id, { resolve, reject, timer });
      this.#socket.send(JSON.stringify({ id, method, params }));
    });
  }

  /** Evaluates an expression in the page and returns its JSON value. */
  async evaluate(expression, timeoutMs = 10_000) {
    const result = await this.send("Runtime.evaluate", {
      expression,
      awaitPromise: true,
      returnByValue: true,
    }, timeoutMs);
    if (result.exceptionDetails) {
      const description = result.exceptionDetails.exception?.description ?? result.exceptionDetails.text;
      throw new Error(`Page evaluation failed: ${description}`);
    }
    return result.result.value;
  }

  async screenshot(file) {
    const { data } = await this.send("Page.captureScreenshot", { format: "png" }, 20_000);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, Buffer.from(data, "base64"));
    return file;
  }

  close() {
    this.#socket.close();
  }
}

/** Starts the debug desktop build against its own data root and debug port. */
export function launchDesktop({ executable, archiveRoot, port, extraEnv = {} }) {
  const child = spawn(executable, [], {
    env: {
      ...process.env,
      LOVELYHAWK_ARCHIVE_ROOT: archiveRoot,
      LOVELYHAWK_DEBUG_PORT: String(port),
      ...extraEnv,
    },
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: false,
  });
  const output = [];
  child.stdout.on("data", (chunk) => output.push(String(chunk)));
  child.stderr.on("data", (chunk) => output.push(String(chunk)));
  return { child, output };
}

/** Connects to the first page whose URL matches `predicate`. */
export async function attach(port, predicate, timeoutMs = 45_000) {
  const target = await waitFor(async () => {
    const targets = await listTargets(port);
    return targets.find((candidate) => predicate(candidate.url)) ?? null;
  }, { timeoutMs, label: "a matching WebView2 page" });
  return { target, session: await CdpSession.connect(target.webSocketDebuggerUrl) };
}
