// Drives the real window against a real lab host, over the same DevTools
// protocol the acceptance probe uses, and checks that a right-click on a line
// of command output reaches the target.
//
// Everything below the window is already covered by probe-paths.mjs. What this
// adds is the one layer that has no other coverage: the click.
//
//   node tools/lab/probe-ui.mjs            # ubuntu
//   LAB=rocky node tools/lab/probe-ui.mjs
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
const which = process.env.LAB ?? "ubuntu";
const container = `lab-${which}`;
const port = 9333;

let failures = 0;
function check(name, actual, expected = true) {
  const ok = actual === expected;
  if (!ok) failures += 1;
  console.log(`  ${ok ? "PASS" : "FAIL"} ${name}${ok ? "" : `\n       expected ${JSON.stringify(expected)}\n       actual   ${JSON.stringify(actual)}`}`);
}

function onHost(command) {
  return execFileSync(
    "wsl.exe",
    ["-d", "Ubuntu", "-u", "root", "-e", "bash", "-lc", `docker exec ${container} sh -c ${JSON.stringify(command)}`],
    { encoding: "utf8" },
  ).split("\0").join("").trim();
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/** Waits for a condition the page can answer, so no step races the render. */
async function waitFor(session, expression, label, attempts = 60) {
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    if (await session.evaluate(expression) === true) return;
    await sleep(500);
  }
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
      // The port is not listening yet.
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
    socket.addEventListener("error", () => reject(new Error("could not attach to the window")));
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
            expression,
            awaitPromise: true,
            returnByValue: true,
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

/** Saves what the operator would be looking at, as evidence for the change. */
async function shot(session, name) {
  const { data } = await session.send("Page.captureScreenshot", { format: "png" });
  const file = path.join(evidence, `${name}.png`);
  fs.writeFileSync(file, Buffer.from(data, "base64"));
  console.log(`      saved ${file}`);
}

const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "lovelyres-ui-"));
let electron;
let session;
try {
  onHost("mkdir -p /usr/local/lib/pyshared && printf '#!/bin/sh\\nexit 0\\n' > /usr/local/lib/pyshared/.helper && chmod 4755 /usr/local/lib/pyshared/.helper");

  // Connecting once through the sidecar records the connection and accepts the
  // host key, so the window opens with a target it can reach straight away.
  console.log(`preparing ${dataRoot} ...`);
  const sidecar = new Sidecar(backend, dataRoot);
  try {
    const status = await connect(sidecar, labTarget(which));
    if (status.stage !== "connected") throw new Error(JSON.stringify(status));
  } finally {
    sidecar.close();
  }

  console.log("launching the window ...");
  // The package exports the path to the real executable, so nothing has to go
  // through a shell wrapper.
  const executable = execFileSync(
    process.execPath,
    ["-e", "process.stdout.write(require('electron'))"],
    { cwd: electronRoot, encoding: "utf8" },
  ).trim();
  electron = spawn(
    executable,
    [".", `--remote-debugging-port=${port}`],
    {
      cwd: electronRoot,
      env: { ...process.env, LOVELYRES_ARCHIVE_ROOT: dataRoot, LOVELYRES_DEBUG: "1" },
      stdio: "ignore",
      shell: false,
      windowsHide: true,
    },
  );

  session = await openSession();
  await session.send("Runtime.enable", {});
  await session.send("Page.enable", {});
  await waitFor(session, "document.querySelector('.connection-card') !== null", "the connection list");

  // --- connect from the window itself
  await session.evaluate(`(() => {
    const card = document.querySelector('.connection-card');
    card?.querySelector('button')?.click() ?? card?.click();
    return true;
  })()`);
  await waitFor(
    session,
    "document.body.textContent.includes('实验靶机') || document.querySelector('.nav-item') !== null",
    "the connected shell",
    120,
  );

  // --- open the command workbench and run the SUID sweep
  await session.evaluate(`(() => {
    const button = [...document.querySelectorAll('.nav-item')]
      .find(candidate => candidate.textContent?.includes('命令工作台'));
    button?.click();
    return true;
  })()`);
  await waitFor(session, "document.querySelector('.emergency-commands-list') !== null", "the catalogue", 120);

  await session.evaluate(`(() => {
    const card = [...document.querySelectorAll('.emergency-commands-list button')]
      .find(candidate => candidate.textContent?.includes('SUID 可执行'));
    card?.click();
    return true;
  })()`);
  await waitFor(session, "document.querySelector('.emergency-command-run') !== null", "the run button");
  await session.evaluate("document.querySelector('.emergency-command-run').click(), true");
  await waitFor(session, "document.querySelector('.emergency-command-output') !== null", "the output", 180);

  const offered = await session.evaluate(`(() => {
    const lines = [...document.querySelectorAll('.emergency-command-output pre span')];
    const actionable = lines.filter(line => line.classList.contains('has-path'));
    return {
      lines: lines.length,
      actionable: actionable.length,
      planted: actionable.some(line => line.textContent.includes('/usr/local/lib/pyshared/.helper')),
      title: actionable[0]?.getAttribute('title') ?? null
    };
  })()`);
  console.log(`\noutput: ${offered.lines} lines, ${offered.actionable} right-clickable`);
  check("the run offered actions on the lines that named a file", offered.actionable > 0);
  check("the planted backdoor is one of them", offered.planted);
  check("the line says what a right-click would touch",
    typeof offered.title === "string" && offered.title.startsWith("右键可对 /"));

  // --- right-click the planted file
  await session.evaluate(`(() => {
    const line = [...document.querySelectorAll('.emergency-command-output pre span.has-path')]
      .find(candidate => candidate.textContent.includes('/usr/local/lib/pyshared/.helper'));
    line.dispatchEvent(new MouseEvent('contextmenu', {
      bubbles: true, cancelable: true, clientX: 200, clientY: 200
    }));
    return true;
  })()`);
  await waitFor(session, "document.querySelector('.emergency-path-menu') !== null", "the menu");
  const menu = await session.evaluate(`(() => {
    const element = document.querySelector('.emergency-path-menu');
    return {
      path: element.querySelector('.emergency-path-menu-title')?.textContent ?? null,
      items: [...element.querySelectorAll('button')].map(button => button.textContent)
    };
  })()`);
  console.log(`\nmenu on ${menu.path}:\n${menu.items.map((item) => `      ${item}`).join("\n")}`);
  check("the menu names the file the line named", menu.path, "/usr/local/lib/pyshared/.helper");
  check("the menu offers the three actions", menu.items.length, 3);
  await shot(session, "right-click-menu");

  // --- read-only first: the properties dialog talks to the target
  await session.evaluate(`(() => {
    [...document.querySelectorAll('.emergency-path-menu button')]
      .find(button => button.textContent.includes('查看属性')).click();
    return true;
  })()`);
  await waitFor(
    session,
    "document.querySelector('[data-testid=\"emergency-path-properties\"] dl') !== null",
    "the properties dialog",
  );
  const properties = await session.evaluate(`(() => {
    const dialog = document.querySelector('[data-testid="emergency-path-properties"]');
    return { text: dialog.textContent, path: dialog.querySelector('header p')?.textContent ?? null };
  })()`);
  check("the properties came from the target", properties.text.includes("4755（rwsr-xr-x）"));
  check("and they are about the file that was clicked", properties.path, "/usr/local/lib/pyshared/.helper");
  await session.evaluate(`(() => {
    [...document.querySelectorAll('[data-testid="emergency-path-properties"] footer button')]
      .find(button => button.textContent.includes('关闭')).click();
    return true;
  })()`);

  // --- then the change, which has to be planned, confirmed and verified
  check("the target is untouched so far", onHost("stat -c %a /usr/local/lib/pyshared/.helper"), "4755");
  await session.evaluate(`(() => {
    const line = [...document.querySelectorAll('.emergency-command-output pre span.has-path')]
      .find(candidate => candidate.textContent.includes('/usr/local/lib/pyshared/.helper'));
    line.dispatchEvent(new MouseEvent('contextmenu', {
      bubbles: true, cancelable: true, clientX: 200, clientY: 200
    }));
    return true;
  })()`);
  await waitFor(session, "document.querySelector('.emergency-path-menu') !== null", "the menu again");
  await session.evaluate(`(() => {
    [...document.querySelectorAll('.emergency-path-menu button')]
      .find(button => button.textContent.includes('去掉执行权限')).click();
    return true;
  })()`);
  await waitFor(
    session,
    "document.querySelector('[data-testid=\"emergency-path-execute\"]:not([disabled])') !== null",
    "the plan",
  );
  const planned = await session.evaluate(
    "document.querySelector('[data-testid=\"emergency-path-dialog\"]').textContent",
  );
  console.log(`\nplan shown to the operator:\n      ${planned.replace(/\s+/gu, " ").slice(0, 300)}`);
  await shot(session, "plan-before-confirm");
  check("the plan says what it will do", planned.includes("from 4755 to 0644"));
  check("and how to undo it", planned.includes("restore the captured permission bits"));
  check("nothing ran while the plan was on screen",
    onHost("stat -c %a /usr/local/lib/pyshared/.helper"), "4755");

  await session.evaluate("document.querySelector('[data-testid=\"emergency-path-execute\"]').click(), true");
  await waitFor(
    session,
    "document.querySelector('[data-testid=\"emergency-path-dialog\"]')?.textContent.includes('目标机反馈') === true",
    "the receipt",
  );
  const receipt = await session.evaluate(
    "document.querySelector('[data-testid=\"emergency-path-dialog\"]').textContent",
  );
  console.log(`\nreceipt shown to the operator:\n      ${receipt.replace(/\s+/gu, " ").slice(0, 240)}`);
  await shot(session, "receipt-after-execute");
  check("the window reports it verified", receipt.includes("已完成，并在目标机上核对过。"));
  check("and the target actually changed",
    onHost("stat -c %a /usr/local/lib/pyshared/.helper"), "644");
  check("the file is still there to examine",
    onHost("test -f /usr/local/lib/pyshared/.helper && echo yes"), "yes");

  console.log(`\n${failures === 0 ? "ALL CHECKS PASSED" : `${failures} CHECK(S) FAILED`}`);
  process.exitCode = failures === 0 ? 0 : 1;
} catch (error) {
  console.log(`\nFAILED: ${error.message}`);
  process.exitCode = 1;
} finally {
  session?.close();
  electron?.kill();
  onHost("rm -f /usr/local/lib/pyshared/.helper");
  await sleep(600);
  fs.rmSync(dataRoot, { recursive: true, force: true });
}
