// Reproduces what the operator did: open the system overview, then switch to
// another lab from the connection list, and watch whether the window keeps a
// working target.
//
//   node tools/lab/probe-ui-switch.mjs
import { execFileSync, spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { Sidecar, connect } from "./rpc-harness.mjs";
import { labTarget } from "./lab-target.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const repository = path.resolve(here, "..", "..");
const electronRoot = path.join(repository, "electron");
const backend = path.join(repository, "target", "debug", "lovelyres-backend.exe");
const port = 9336;
// The order the operator would click them in.
const LABS = ["arena", "nginx", "redis"];

let failures = 0;
function check(name, actual, expected = true) {
  const ok = actual === expected;
  if (!ok) failures += 1;
  console.log(`  ${ok ? "PASS" : "FAIL"} ${name}${ok ? "" : `\n       expected ${JSON.stringify(expected)}\n       actual   ${JSON.stringify(actual)}`}`);
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function waitFor(session, expression, label, attempts = 120) {
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    if (await session.evaluate(expression) === true) return true;
    await sleep(500);
  }
  // What the window was actually showing when it gave up, so a timeout points
  // at the state rather than only at the wait that failed.
  const seen = await session.evaluate(`(() => ({
    page: document.querySelector('.content .page, .content main')?.className ?? '(none)',
    heading: document.querySelector('.content h1, .content h2')?.textContent ?? '',
    status: document.querySelector('.statusbar-target')?.textContent ?? '',
    error: document.querySelector('.statusbar-error')?.textContent ?? '',
    alerts: [...document.querySelectorAll('[role=alert],[role=status]')]
      .map(n => n.textContent.trim()).filter(Boolean).slice(0, 4).join(' | '),
    tables: document.querySelectorAll('.system-info-table-scroll').length,
    rows: document.querySelectorAll('.system-info-table-scroll tbody tr').length,
    tabs: [...document.querySelectorAll('.system-info-tabs button')]
      .map(b => b.textContent.trim()).slice(0, 8),
    panel: document.querySelector('.system-info-table-panel')?.textContent.slice(0, 160) ?? '(no panel)'
  }))()`).catch(() => null);
  console.log(`  当时页面：${JSON.stringify(seen)}`);
  throw new Error(`timed out waiting for ${label}`);
}

async function openSession() {
  for (let attempt = 0; attempt < 60; attempt += 1) {
    try {
      const targets = await fetch(`http://127.0.0.1:${port}/json/list`).then((r) => r.json());
      const page = targets.find((target) =>
        target.type === "page" && String(target.url).startsWith("lovelyres://app/") &&
        !String(target.url).includes("window=terminal"));
      if (page !== undefined) return await attach(page.webSocketDebuggerUrl);
    } catch {
      // Not listening yet.
    }
    await sleep(500);
  }
  throw new Error("the window never exposed a debugging target");
}

function attach(url) {
  return new Promise((resolve, reject) => {
    const socket = new WebSocket(url);
    const pending = new Map();
    let nextId = 1;
    socket.addEventListener("message", (event) => {
      const message = JSON.parse(String(event.data));
      const waiting = pending.get(message.id);
      if (waiting === undefined) return;
      pending.delete(message.id);
      if (message.error !== undefined) waiting.reject(new Error(JSON.stringify(message.error)));
      else waiting.resolve(message.result);
    });
    socket.addEventListener("error", () => reject(new Error("could not attach")));
    socket.addEventListener("open", () => {
      const send = (method, params) => new Promise((res, rej) => {
        const id = nextId++;
        pending.set(id, { resolve: res, reject: rej });
        socket.send(JSON.stringify({ id, method, params }));
        setTimeout(() => {
          if (pending.delete(id)) rej(new Error(`${method} timed out`));
        }, 30_000);
      });
      resolve({
        send,
        close: () => socket.close(),
        async evaluate(expression) {
          const result = await send("Runtime.evaluate", {
            expression, awaitPromise: true, returnByValue: true,
          });
          if (result.exceptionDetails !== undefined) {
            throw new Error(result.exceptionDetails.exception?.description ?? "evaluate threw");
          }
          return result.result.value;
        },
      });
    });
  });
}

const evidence = path.join(repository, "target", "lab-ui");
fs.mkdirSync(evidence, { recursive: true });
const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "lovelyres-switch-"));
let electron;
let session;

/** What the status bar says about the target right now. */
const TARGET_STATE = `(() => ({
  target: document.querySelector('.statusbar-target')?.textContent ?? '',
  error: document.querySelector('.statusbar-error')?.textContent ?? '',
  rows: document.querySelectorAll('.system-info-table-scroll tbody tr').length,
  panel: (document.querySelector('.system-info-table-panel')?.textContent ?? '').slice(0, 120),
  pagePrompt: document.querySelector('.system-info-connect-prompt')?.textContent ?? '',
  pageError: [...document.querySelectorAll('[role=alert]')].map(n => n.textContent).join(' | ')
}))()`;

try {
  // Recording every host key up front is what the window does once the
  // operator has confirmed each of them, so the switch itself is what is
  // being measured rather than the prompts.
  console.log(`准备连接库 ${dataRoot} …`);
  const sidecar = new Sidecar(backend, dataRoot);
  try {
    for (const [index, name] of LABS.entries()) {
      const id = `bbbbbbbb-0000-4000-8000-00000000000${index + 1}`;
      const status = await connect(sidecar, { ...labTarget(name), id, name: `实验靶机 ${name}` });
      if (status.stage !== "connected") throw new Error(`${name}: ${JSON.stringify(status)}`);
      await sidecar.call("ssh.binding.disconnect", { bindingHandle: status.bindingHandle });
      console.log(`  ${name} 已记录`);
    }
  } finally {
    sidecar.close();
  }

  const executable = execFileSync(
    process.execPath, ["-e", "process.stdout.write(require('electron'))"],
    { cwd: electronRoot, encoding: "utf8" },
  ).trim();
  electron = spawn(executable, [".", `--remote-debugging-port=${port}`], {
    cwd: electronRoot,
    env: { ...process.env, LOVELYRES_ARCHIVE_ROOT: dataRoot, LOVELYRES_DEBUG: "1" },
    stdio: "ignore", shell: false, windowsHide: true,
  });

  session = await openSession();
  await session.send("Runtime.enable", {});
  await session.send("Page.enable", {});
  await waitFor(session, "document.querySelectorAll('.connection-card').length >= 3", "the list");

  for (const [index, name] of LABS.entries()) {
    console.log(`\n=== 第 ${index + 1} 次：切到 ${name} ===`);
    await session.evaluate(`(() => {
      const card = [...document.querySelectorAll('.connection-card')][${index}];
      [...card.querySelectorAll('button')].find(b => b.textContent?.includes('连接'))?.click();
      return true;
    })()`);
    await waitFor(session, "document.querySelector('.nav-item') !== null", "the shell", 180);

    // Open the system overview. It lands on the live-status tab, which is not
    // a table, so the first real read is the one after that.
    await session.evaluate(`(() => {
      [...document.querySelectorAll('.nav-item')]
        .find(c => c.textContent?.includes('主机全景'))?.click();
      return true;
    })()`);
    await waitFor(session, "document.querySelector('.system-info-tabs') !== null", "the page", 180);
    await session.evaluate(`(() => {
      [...document.querySelectorAll('.system-info-tabs button')]
        .find(b => b.textContent?.trim() === '系统信息')?.click();
      return true;
    })()`);
    await waitFor(
      session,
      "(document.querySelector('.system-info-table-panel')?.textContent ?? '').includes('操作系统')",
      "the overview table",
      180,
    );

    // Read a few more tabs, the way an operator works down the page.
    const tabs = await session.evaluate(`(() => {
      const buttons = [...document.querySelectorAll('.system-info-tabs button')].slice(2, 6);
      buttons.forEach(b => b.click());
      return buttons.length;
    })()`);
    await sleep(6000);

    const state = await session.evaluate(TARGET_STATE);
    console.log(`  状态栏：${state.target.trim()}`);
    if (state.error !== "") console.log(`  状态栏报错：${state.error}`);
    if (state.pageError !== "") console.log(`  页面报错：${state.pageError.slice(0, 200)}`);
    console.log(`  面板：${state.panel.replace(/\s+/gu, " ").slice(0, 90)}`);
    console.log(`  表格行数：${state.rows}，之后又点了 ${tabs} 个标签页`);

    check(`${name}：状态栏仍显示已连接`, state.target.includes("断开"), true);
    check(`${name}：状态栏没有报错`, state.error, "");
    check(`${name}：主机全景读到了数据`, state.rows > 0 || state.panel.length > 0, true);
    check(`${name}：页面没有报错`, state.pageError, "");
  }

  const { data } = await session.send("Page.captureScreenshot", { format: "png" });
  fs.writeFileSync(path.join(evidence, "switch-targets.png"), Buffer.from(data, "base64"));

  console.log(`\n${failures === 0 ? "ALL CHECKS PASSED" : `${failures} CHECK(S) FAILED`}`);
  process.exitCode = failures === 0 ? 0 : 1;
} catch (error) {
  console.log(`\nFAILED: ${error.message}`);
  process.exitCode = 1;
} finally {
  session?.close();
  electron?.kill();
  await sleep(600);
  fs.rmSync(dataRoot, { recursive: true, force: true });
}
