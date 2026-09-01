// Drives the real window against a real lab host and checks that a right-click
// on a system-information row reaches the target: first a read-only action,
// then a change that has to be planned, confirmed and verified.
//
//   node tools/lab/probe-ui-system-info.mjs            # ubuntu
//   LAB=rocky node tools/lab/probe-ui-system-info.mjs
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
const port = 9334;
/** A process nobody else on the host runs, so the row is unmistakable. */
const marker = "sleep 36001";

let failures = 0;
function check(name, actual, expected = true) {
  const ok = actual === expected;
  if (!ok) failures += 1;
  console.log(`  ${ok ? "PASS" : "FAIL"} ${name}${ok ? "" : `\n       expected ${JSON.stringify(expected)}\n       actual   ${JSON.stringify(actual)}`}`);
}

/**
 * Runs one command inside the container. Single-quoted for the bash on the
 * WSL side, so `$!` and friends are expanded by the shell in the container
 * and not by the one that merely carries the text across.
 */
function onHost(command) {
  const quoted = `'${command.replace(/'/gu, `'\\''`)}'`;
  return execFileSync(
    "wsl.exe",
    ["-d", "Ubuntu", "-u", "root", "-e", "bash", "-lc", `docker exec ${container} sh -c ${quoted}`],
    { encoding: "utf8" },
  ).split("\0").join("").trim();
}

/** Kills any planted sleeper a previous run left behind. */
function cleanPlanted() {
  onHost(`for p in $(pgrep -x sleep); do grep -q 36001 /proc/$p/cmdline 2>/dev/null && kill -9 $p; done; true`);
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

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

const evidence = path.join(repository, "target", "lab-ui-system-info");
fs.mkdirSync(evidence, { recursive: true });

async function shot(session, name) {
  const { data } = await session.send("Page.captureScreenshot", { format: "png" });
  const file = path.join(evidence, `${name}.png`);
  fs.writeFileSync(file, Buffer.from(data, "base64"));
  console.log(`      saved ${file}`);
}

/** Right-clicks the command cell of the row whose text contains `text`. */
function contextMenuOnRow(session, text) {
  return session.evaluate(`(() => {
    const row = [...document.querySelectorAll('.system-info-table-scroll tbody tr')]
      .find(candidate => candidate.textContent.includes(${JSON.stringify(text)}));
    if (row === undefined) return false;
    const cells = row.querySelectorAll('td');
    const cell = cells[cells.length - 3] ?? row;
    cell.dispatchEvent(new MouseEvent('contextmenu', {
      bubbles: true, cancelable: true, clientX: 300, clientY: 300
    }));
    return true;
  })()`);
}

function readMenu(session) {
  return session.evaluate(`(() => {
    const element = document.querySelector('.system-info-row-menu');
    if (element === null) return null;
    return {
      title: element.querySelector('.system-info-row-menu-title')?.textContent ?? null,
      groups: [...element.querySelectorAll('.system-info-row-menu-group h3')].map(h => h.textContent),
      items: [...element.querySelectorAll('button')].map(button => button.textContent),
      dangerous: [...element.querySelectorAll('button.is-dangerous')].map(button => button.textContent),
      selected: document.querySelector('.system-info-table-scroll tbody tr.is-selected')?.textContent ?? null,
    };
  })()`);
}

function clickMenuItem(session, label) {
  return session.evaluate(`(() => {
    const button = [...document.querySelectorAll('.system-info-row-menu button')]
      .find(candidate => candidate.textContent.includes(${JSON.stringify(label)}));
    if (button === undefined) return false;
    button.click();
    return true;
  })()`);
}

function selectTab(session, label) {
  return session.evaluate(`(() => {
    const button = [...document.querySelectorAll('.system-info-tabs button')]
      .find(candidate => candidate.textContent.trim() === ${JSON.stringify(label)});
    if (button === undefined) return false;
    button.click();
    return true;
  })()`);
}

const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "lovelyres-ui-sysinfo-"));
let electron;
let session;
let plantedPid = "";
try {
  cleanPlanted();
  plantedPid = onHost(`nohup ${marker} >/dev/null 2>&1 & echo $!`);
  if (!/^[0-9]+$/u.test(plantedPid)) throw new Error(`could not plant a process: ${plantedPid}`);
  check("the planted process is running on the host", onHost(`kill -0 ${plantedPid} && echo alive`), "alive");

  console.log(`preparing ${dataRoot} ...`);
  const sidecar = new Sidecar(backend, dataRoot);
  try {
    const status = await connect(sidecar, labTarget(which));
    if (status.stage !== "connected") throw new Error(JSON.stringify(status));
  } finally {
    sidecar.close();
  }

  console.log("launching the window ...");
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

  // --- the system-information page, processes tab
  await session.evaluate(`(() => {
    const button = [...document.querySelectorAll('.nav-item')]
      .find(candidate => candidate.textContent?.includes('主机全景'));
    button?.click();
    return true;
  })()`);
  await waitFor(session, "document.querySelector('.system-info-tabs') !== null", "the page", 120);
  check("the processes tab exists", await selectTab(session, "进程详情"));
  await waitFor(
    session,
    `[...document.querySelectorAll('.system-info-table-scroll tbody tr')].some(row => row.textContent.includes(${JSON.stringify(marker)}))`,
    "the planted process in the table",
    120,
  );

  // --- the menu
  check("the planted row can be right-clicked", await contextMenuOnRow(session, marker));
  await waitFor(session, "document.querySelector('.system-info-row-menu-group') !== null", "the menu actions");
  const menu = await readMenu(session);
  console.log(`\nmenu on ${menu.title}:\n      groups: ${menu.groups.join(" / ")}\n      ${menu.items.length} items, ${menu.dangerous.length} dangerous`);
  check("the menu names the process by PID", menu.title?.includes(`PID ${plantedPid}`) === true);
  check("the row stays marked while the menu is open", menu.selected?.includes(marker) === true);
  check("the local items come first", menu.items[0], "复制这一格");
  check("the read-only groups are there", menu.groups.includes("基本信息") && menu.groups.includes("安全检测"));
  check("the change group is last", menu.groups[menu.groups.length - 1], "处置");
  check("the signals are painted dangerous", menu.dangerous.includes("强制终止进程（SIGKILL）"));
  await shot(session, "process-menu");

  // --- read-only first
  check("the command line action is offered", await clickMenuItem(session, "命令行参数"));
  await waitFor(
    session,
    "document.querySelector('[data-testid=\"system-info-row-action-output\"]') !== null",
    "the inspection output",
    120,
  );
  const output = await session.evaluate(
    "document.querySelector('[data-testid=\"system-info-row-action-output\"]').textContent",
  );
  console.log(`\ninspection output:\n      ${output.replace(/\s+/gu, " ").slice(0, 200)}`);
  check("the output came from the target and is about this process", output.includes(marker));
  await shot(session, "process-command-line");
  await session.evaluate(`(() => {
    [...document.querySelectorAll('[data-testid="system-info-row-action-dialog"] header button')]
      .find(button => button.textContent.includes('关闭')).click();
    return true;
  })()`);
  await waitFor(session, "document.querySelector('[data-testid=\"system-info-row-action-dialog\"]') === null", "the dialog to close");

  // --- then the change, which has to be planned, confirmed and verified
  check("the target is untouched so far", onHost(`kill -0 ${plantedPid} && echo alive`), "alive");
  check("the row can be right-clicked again", await contextMenuOnRow(session, marker));
  await waitFor(session, "document.querySelector('.system-info-row-menu-group') !== null", "the menu again");
  check("the kill action is offered", await clickMenuItem(session, "强制终止进程（SIGKILL）"));
  await waitFor(
    session,
    "document.querySelector('[data-testid=\"system-info-row-action-execute\"]:not([disabled])') !== null",
    "the plan",
    120,
  );
  const planned = await session.evaluate(
    "document.querySelector('[data-testid=\"system-info-row-action-dialog\"]').textContent",
  );
  console.log(`\nplan shown to the operator:\n      ${planned.replace(/\s+/gu, " ").slice(0, 300)}`);
  await shot(session, "kill-plan-before-confirm");
  check("the plan names the signal and the PID", planned.includes("SIGKILL") && planned.includes(`PID ${plantedPid}`));
  check("the plan says it cannot be undone", planned.includes("不可恢复"));
  check("nothing ran while the plan was on screen", onHost(`kill -0 ${plantedPid} && echo alive`), "alive");

  await session.evaluate("document.querySelector('[data-testid=\"system-info-row-action-execute\"]').click(), true");
  await waitFor(
    session,
    "document.querySelector('[data-testid=\"system-info-row-action-dialog\"]')?.textContent.includes('目标机反馈') === true",
    "the receipt",
    120,
  );
  const receipt = await session.evaluate(
    "document.querySelector('[data-testid=\"system-info-row-action-dialog\"]').textContent",
  );
  console.log(`\nreceipt shown to the operator:\n      ${receipt.replace(/\s+/gu, " ").slice(0, 240)}`);
  await shot(session, "kill-receipt");
  check("the window reports it verified", receipt.includes("已完成，并在目标机上核对过。"));
  // The lab container's PID 1 is `sleep infinity`, which never reaps, so a
  // killed child lingers as a zombie: dead, but still listed. Dead is what
  // matters here.
  check("and the process is actually gone",
    onHost(`[ -r /proc/${plantedPid}/stat ] || { echo gone; exit 0; }; s=$(cat /proc/${plantedPid}/stat); r=\${s##*) }; case "\${r%% *}" in Z) echo gone;; *) echo alive;; esac`),
    "gone");
  await session.evaluate(`(() => {
    [...document.querySelectorAll('[data-testid="system-info-row-action-dialog"] footer button')]
      .find(button => button.textContent.includes('关闭')).click();
    return true;
  })()`);

  // --- a network row: a listening port has no peer, so no disconnect is offered
  check("the open ports tab exists", await selectTab(session, "开放端口"));
  await waitFor(
    session,
    "document.querySelector('.system-info-table-scroll tbody tr') !== null",
    "the open ports table",
    120,
  );
  check("a port row can be right-clicked", await contextMenuOnRow(session, ":22") || await contextMenuOnRow(session, "sshd") || await contextMenuOnRow(session, "22"));
  await waitFor(session, "document.querySelector('.system-info-row-menu-group') !== null || document.querySelector('.system-info-row-menu-note') !== null", "the port menu");
  const portMenu = await readMenu(session);
  console.log(`\nport menu on ${portMenu.title}:\n      groups: ${portMenu.groups.join(" / ")}`);
  check("a listening port gets port analysis", portMenu.groups.includes("端口分析"));
  check("but nothing to disconnect", !portMenu.items.includes("断开此连接"));
  await shot(session, "port-menu");
  check("the port process action is offered", await clickMenuItem(session, "查看占用进程"));
  await waitFor(
    session,
    "document.querySelector('[data-testid=\"system-info-row-action-output\"]') !== null",
    "the port inspection output",
    120,
  );
  const portOutput = await session.evaluate(
    "document.querySelector('[data-testid=\"system-info-row-action-output\"]').textContent",
  );
  console.log(`\nport inspection output:\n      ${portOutput.replace(/\s+/gu, " ").slice(0, 200)}`);
  check("the port inspection answered", portOutput.trim().length > 0);
  await shot(session, "port-process");

  console.log(`\n${failures === 0 ? "ALL CHECKS PASSED" : `${failures} CHECK(S) FAILED`}`);
  process.exitCode = failures === 0 ? 0 : 1;
} catch (error) {
  console.log(`\nFAILED: ${error.message}`);
  process.exitCode = 1;
} finally {
  session?.close();
  electron?.kill();
  cleanPlanted();
  await sleep(600);
  fs.rmSync(dataRoot, { recursive: true, force: true });
}
