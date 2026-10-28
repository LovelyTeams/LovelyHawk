// Drives the real window against a real lab host and checks that a right-click
// on a system-information row reaches the target: first a read-only action,
// then a change that has to be planned, confirmed and verified.
//
//   node tools/lab/probe-ui-system-info.mjs            # ubuntu
//   LAB=rocky node tools/lab/probe-ui-system-info.mjs
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { startDesktop } from "./desktop.mjs";
import { Sidecar, connect } from "./rpc-harness.mjs";
import { labTarget } from "./lab-target.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const repository = path.resolve(here, "..", "..");
const backend = path.join(repository, "target", "debug", "lovelyhawk-backend.exe");
const which = process.env.LAB ?? "ubuntu";
const container = `lab-${which}`;
// Configurable so a run cannot collide with a debugging port another probe
// (or a previous run that has not let go of it yet) is still holding.
const port = Number(process.env.LAB_UI_PORT ?? 9334);
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

/**
 * Kills any planted sleeper a previous run left behind.
 *
 * Walks /proc rather than calling pgrep: the busybox images do not all have
 * it, and /proc is the one thing every target here agrees on. The name is
 * checked before the arguments, because the shell running this very loop has
 * the marker in its own command line and would otherwise kill itself.
 */
function cleanPlanted() {
  onHost(
    `for d in /proc/[0-9]*; do p=\${d#/proc/}; [ "$p" = "$$" ] && continue; ` +
    `c=$(cat "$d/comm" 2>/dev/null) || continue; [ "$c" = "sleep" ] || continue; ` +
    `tr '\\0' ' ' < "$d/cmdline" 2>/dev/null | grep -q 36001 && kill -9 "$p" 2>/dev/null; done; true`,
  );
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function waitFor(session, expression, label, attempts = 60) {
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    if (await session.evaluate(expression) === true) return;
    await sleep(500);
  }
  throw new Error(`timed out waiting for ${label}`);
}

/**
 * Waits for the target's own actions to fill the menu, and says what was on
 * screen instead when they do not.
 *
 * A bare "timed out" is not actionable: the menu showing an error, the menu
 * saying the row has nothing, and the menu never opening at all are three
 * different bugs that look identical from the outside.
 */
async function waitForMenuActions(session, label) {
  try {
    await waitFor(session, "document.querySelector('.system-info-row-menu-parent') !== null", label);
  } catch (error) {
    const state = await session.evaluate(`(() => {
      const menu = document.querySelector('.system-info-row-menu');
      return {
        menuPresent: menu !== null,
        text: menu?.textContent?.slice(0, 400) ?? null,
        note: menu?.querySelector('.system-info-row-menu-note')?.textContent ?? null,
        dialog: document.querySelector('[data-testid="system-info-row-action-dialog"]')?.textContent?.slice(0, 200) ?? null,
        rows: document.querySelectorAll('.system-info-table-scroll tbody tr').length,
      };
    })()`);
    console.log(`      menu state at timeout: ${JSON.stringify(state)}`);
    await shot(session, `timeout-${label.replace(/\s+/gu, "-")}`);
    throw error;
  }
}

/**
 * Waits for a step of the action dialog, and says what the dialog was showing
 * when it does not arrive — an error the target returned looks exactly like a
 * request still in flight from the outside.
 */
async function waitForDialog(session, expression, label, attempts = 120) {
  try {
    await waitFor(session, expression, label, attempts);
  } catch (error) {
    const text = await session.evaluate(
      `document.querySelector('[data-testid="system-info-row-action-dialog"]')?.textContent?.slice(0, 400) ?? null`,
    );
    console.log(`      dialog at timeout: ${JSON.stringify(text)}`);
    await shot(session, `timeout-${label.replace(/\s+/gu, "-")}`);
    throw error;
  }
}

// One directory per target, so a sweep across the matrix keeps every target's
// screenshots instead of each one overwriting the last.
const evidence = path.join(repository, "target", "lab-ui-system-info", which);
fs.mkdirSync(evidence, { recursive: true });

async function shot(session, name) {
  const { data } = await session.send("Page.captureScreenshot", { format: "png" });
  const file = path.join(evidence, `${name}.png`);
  fs.writeFileSync(file, Buffer.from(data, "base64"));
  console.log(`      saved ${file}`);
}

/**
 * The PID cell of a process row, found by its column header. A fixed index
 * broke once the table stopped repeating the risk column (级别 shows it).
 */
const PID_CELL = `(row) => row.querySelectorAll('td')[[...document.querySelectorAll('.system-info-table-scroll thead th')].findIndex(th => th.textContent.trim() === 'PID')]`;

/**
 * Right-clicks the process row whose PID cell is exactly this PID.
 *
 * Matching the command text instead picks the first row that merely mentions
 * it, and on a host that has run this probe before that can be a different
 * process entirely — which then fails at the plan, because the core checks the
 * PID it was given and not the words next to it.
 */
function contextMenuOnPid(session, pid) {
  return session.evaluate(`(() => {
    const row = [...document.querySelectorAll('.system-info-table-scroll tbody tr')]
      .find(candidate => (${PID_CELL})(candidate)?.textContent.trim() === ${JSON.stringify(String(pid))});
    if (row === undefined) return false;
    const cells = row.querySelectorAll('td');
    const cell = cells[cells.length - 3] ?? row;
    cell.dispatchEvent(new MouseEvent('contextmenu', {
      bubbles: true, cancelable: true, clientX: 300, clientY: 300
    }));
    return true;
  })()`);
}

/** Right-clicks the first row of whatever table is showing. */
function contextMenuOnFirstRow(session) {
  return session.evaluate(`(() => {
    const row = document.querySelector('.system-info-table-scroll tbody tr');
    if (row === null) return false;
    (row.querySelector('td') ?? row).dispatchEvent(new MouseEvent('contextmenu', {
      bubbles: true, cancelable: true, clientX: 300, clientY: 300
    }));
    return true;
  })()`);
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
      // Each group is one entry whose actions sit in its submenu.
      groups: [...element.querySelectorAll('.system-info-row-menu-parent .system-info-row-menu-label')].map(label => label.textContent),
      items: [...element.querySelectorAll('button:not(.system-info-row-menu-parent)')].map(button => button.textContent),
      dangerous: [...element.querySelectorAll('button.is-dangerous')].map(button => button.textContent),
      selected: document.querySelector('.system-info-table-scroll tbody tr.is-selected')?.textContent ?? null,
    };
  })()`);
}

/**
 * Clicks an action the way an operator reaches it: opens its group first, and
 * only clicks the action once its submenu is actually showing.
 */
function clickMenuItem(session, label) {
  return session.evaluate(`(async () => {
    const button = [...document.querySelectorAll('.system-info-row-menu button:not(.system-info-row-menu-parent)')]
      .find(candidate => candidate.textContent.includes(${JSON.stringify(label)}));
    if (button === undefined) return false;
    const submenu = button.closest('.system-info-row-submenu');
    if (submenu !== null) {
      if (submenu.hidden) submenu.previousElementSibling.click();
      for (let frame = 0; frame < 60 && (submenu.hidden || submenu.style.visibility === 'hidden'); frame += 1) {
        await new Promise(resolve => setTimeout(resolve, 16));
      }
      if (submenu.hidden || submenu.style.visibility === 'hidden') return false;
    }
    button.click();
    return true;
  })()`);
}

/**
 * Selects a tab, and does not click one that is already selected.
 *
 * Clicking the active tab re-collects it, which is what an operator asking for
 * a refresh wants — but it also mints a new snapshot, and a new snapshot
 * closes any menu opened against the old one. On a host with hundreds of
 * processes that second collect lands seconds later, so a probe that clicks
 * anyway is racing itself rather than testing the menu.
 */
function selectTab(session, label) {
  return session.evaluate(`(() => {
    const button = [...document.querySelectorAll('.system-info-tabs button')]
      .find(candidate => candidate.textContent.trim() === ${JSON.stringify(label)});
    if (button === undefined) return false;
    if (button.getAttribute('aria-pressed') !== 'true') button.click();
    return true;
  })()`);
}

/**
 * Waits until the table has stopped being replaced.
 *
 * A collect in flight is visible as the "正在采集" state; a collect that has
 * just landed shows up as a changed row count. Both have to be quiet before a
 * row id is worth right-clicking.
 */
async function waitForTableSettled(session, attempts = 120) {
  let previous = -1;
  let stable = 0;
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    const state = await session.evaluate(`(() => ({
      collecting: [...document.querySelectorAll('.system-info-table-state')]
        .some(element => element.textContent.includes('正在采集')),
      rows: document.querySelectorAll('.system-info-table-scroll tbody tr').length,
    }))()`);
    stable = !state.collecting && state.rows > 0 && state.rows === previous ? stable + 1 : 0;
    previous = state.rows;
    if (stable >= 4) return state.rows;
    await sleep(500);
  }
  throw new Error("the table never settled");
}

const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "lovelyhawk-ui-sysinfo-"));
let app;
let session;
let plantedPid = "";
try {
  cleanPlanted();
  plantedPid = onHost(`nohup ${marker} >/dev/null 2>&1 & echo $!`);
  if (!/^[0-9]+$/u.test(plantedPid)) throw new Error(`could not plant a process: ${plantedPid}`);
  check("the planted process is running on the host", onHost(`kill -0 ${plantedPid} && echo alive`), "alive");
  console.log(`      planted pid=${plantedPid} on ${which}`);

  console.log(`preparing ${dataRoot} ...`);
  const sidecar = new Sidecar(backend, dataRoot);
  try {
    const status = await connect(sidecar, labTarget(which));
    if (status.stage !== "connected") throw new Error(JSON.stringify(status));
  } finally {
    sidecar.close();
  }

  console.log("launching the window ...");
  app = await startDesktop({ dataRoot, port });
  session = app.session;
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
  try {
    await waitFor(
      session,
      `[...document.querySelectorAll('.system-info-table-scroll tbody tr')].some(row => (${PID_CELL})(row)?.textContent.trim() === ${JSON.stringify(String(plantedPid))})`,
      "the planted process in the table",
      120,
    );
  } catch (error) {
    // The table stops at five hundred rows. This container's PID 1 is
    // `sleep infinity`, which never reaps, so every command any probe has
    // ever run is still listed as a zombie — and a freshly planted process
    // has the highest PID of all, so it is the first thing off the end.
    const rows = await session.evaluate(
      "document.querySelectorAll('.system-info-table-scroll tbody tr').length",
    );
    const truncated = await session.evaluate(
      "document.querySelector('.system-info-truncated') !== null",
    );
    const zombies = onHost("z=0; for d in /proc/[0-9]*; do s=$(cat \"$d/stat\" 2>/dev/null) || continue; r=${s##*) }; case \"${r%% *}\" in Z) z=$((z+1));; esac; done; echo \"$z\"");
    console.log(`      table shows ${rows} rows (truncated=${truncated}); the host has ${zombies} zombies`);
    if (truncated) {
      console.log("      the planted process is past the 500-row ceiling; restart this container to clear the zombies");
    }
    throw error;
  }
  console.log(`      process table settled at ${await waitForTableSettled(session)} rows`);

  // --- the layout: the page fills the window and the table scrolls inside it.
  // It used to grow with the table instead, so the page scrolled: the column
  // headers went with it and the last rows sat under the status bar.
  const layout = await session.evaluate(`(() => {
    const content = document.querySelector('.content');
    const scroll = document.querySelector('.system-info-table-scroll');
    const pageScrolls = content.scrollHeight > content.clientHeight + 1;
    const tableBottom = scroll.getBoundingClientRect().bottom;
    const contentBottom = content.getBoundingClientRect().bottom;
    scroll.scrollTop = scroll.scrollHeight;
    const box = scroll.getBoundingClientRect();
    const rows = scroll.querySelectorAll('tbody tr');
    const last = rows[rows.length - 1].getBoundingClientRect();
    const head = scroll.querySelector('thead th').getBoundingClientRect();
    const result = {
      pageScrolls,
      tableInside: tableBottom <= contentBottom,
      lastInside: last.bottom <= box.bottom + 1 && last.top >= box.top,
      headAtTop: Math.abs(head.top - box.top) <= 2,
    };
    scroll.scrollTop = 0;
    return result;
  })()`);
  check("the page does not scroll as a whole", layout.pageScrolls, false);
  check("the table ends above the status bar", layout.tableInside);
  check("the last row scrolls into view inside the table", layout.lastInside);
  check("the column headers stay in view", layout.headAtTop);

  // --- the menu
  check("the planted row can be right-clicked", await contextMenuOnPid(session, plantedPid));
  await waitForMenuActions(session, "the menu actions");
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
  await waitForDialog(
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
  check("the row can be right-clicked again", await contextMenuOnPid(session, plantedPid));
  await waitForMenuActions(session, "the menu again");
  check("the kill action is offered", await clickMenuItem(session, "强制终止进程（SIGKILL）"));
  await waitForDialog(
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
  // How long the plan is good for, read out loud. It used to print the raw
  // seconds, which asked an operator to divide three hundred by sixty on the
  // one screen where they are about to kill something.
  check("the plan says its window in minutes", planned.includes("5 分钟"));
  check("and not as a number to divide", planned.includes("300 秒"), false);
  check("nothing ran while the plan was on screen", onHost(`kill -0 ${plantedPid} && echo alive`), "alive");

  await session.evaluate("document.querySelector('[data-testid=\"system-info-row-action-execute\"]').click(), true");
  await waitForDialog(
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
  // The readback is shown as is, so it has to be in the operator's language.
  check("the readback says the process ended, in Chinese", receipt.includes(`确认时的进程 PID ${plantedPid} 已经结束`));
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
  await waitForTableSettled(session);
  check("a port row can be right-clicked", await contextMenuOnRow(session, ":22") || await contextMenuOnRow(session, "sshd") || await contextMenuOnRow(session, "22"));
  // The groups, or a note that is not "still reading": the loading note is a
  // note too, and reading the menu while it shows found no groups at all.
  await waitFor(session, "document.querySelector('.system-info-row-menu-parent') !== null || [...document.querySelectorAll('.system-info-row-menu-note')].some(note => note.getAttribute('role') !== 'status')", "the port menu");
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
  await session.evaluate(`(() => {
    [...document.querySelectorAll('[data-testid="system-info-row-action-dialog"] header button')]
      .find(button => button.textContent.includes('关闭')).click();
    return true;
  })()`);

  // --- a boot entry, which on a host that does not boot with systemd is a
  //     script; those rows listed fine and offered nothing at all.
  check("the autostart tab exists", await selectTab(session, "自启动"));
  await waitFor(
    session,
    "document.querySelector('.system-info-table-scroll tbody tr') !== null",
    "the autostart table",
    120,
  );
  await waitForTableSettled(session);
  const bootKind = await session.evaluate(
    "document.querySelector('.system-info-table-scroll tbody tr td:nth-child(4)')?.textContent ?? null",
  );
  check("a boot entry can be right-clicked", await contextMenuOnFirstRow(session));
  await waitForMenuActions(session, "the boot entry menu");
  const bootMenu = await readMenu(session);
  console.log(`\nboot entry menu (${bootKind}) on ${bootMenu.title}:\n      groups: ${bootMenu.groups.join(" / ")}\n      ${bootMenu.items.length} items`);
  check("the boot entry offers more than the window's own items", bootMenu.items.length > 3);
  check("it offers investigation", bootMenu.groups.length > 0);
  // Everything this tab lists already starts at boot, so taking it out is the
  // change on offer — on a host that has something to change boot links with.
  console.log(`      change group present: ${bootMenu.groups.includes("处置")}`);
  await shot(session, "autostart-menu");
  check("the boot entry's script can be read", await clickMenuItem(session, "启动文件内容"));
  await waitForDialog(
    session,
    "document.querySelector('[data-testid=\"system-info-row-action-output\"]') !== null",
    "the boot script output",
    120,
  );
  const bootOutput = await session.evaluate(
    "document.querySelector('[data-testid=\"system-info-row-action-output\"]').textContent",
  );
  console.log(`\nboot entry file, first lines:\n      ${bootOutput.split("\n").slice(0, 3).join(" | ").slice(0, 180)}`);
  if (bootKind === "init.d") {
    check("the script came back from the target", bootOutput.trim().length > 0);
  } else {
    // A systemd row answers through systemctl, which has nothing to say in a
    // container that never booted with systemd. That path is unchanged here.
    console.log(`      systemd row, ${bootOutput.trim().length} bytes back`);
  }
  await shot(session, "autostart-script");

  console.log(`\n${failures === 0 ? "ALL CHECKS PASSED" : `${failures} CHECK(S) FAILED`}`);
  process.exitCode = failures === 0 ? 0 : 1;
} catch (error) {
  console.log(`\nFAILED: ${error.message}`);
  process.exitCode = 1;
} finally {
  await app?.close();
  cleanPlanted();
  fs.rmSync(dataRoot, { recursive: true, force: true, maxRetries: 10, retryDelay: 300 });
}
