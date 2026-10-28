// Drives the real window against a real lab host, over the same DevTools
// protocol the acceptance probe uses, and checks that a right-click on a line
// of command output reaches the target.
//
// Everything below the window is already covered by probe-paths.mjs. What this
// adds is the one layer that has no other coverage: the click.
//
//   node tools/lab/probe-ui.mjs            # ubuntu
//   LAB=rocky node tools/lab/probe-ui.mjs
import { execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { startDesktop } from "./desktop.mjs";
import { Sidecar, connect } from "./rpc-harness.mjs";
import { isLinuxLab, labTarget } from "./lab-target.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const repository = path.resolve(here, "..", "..");
const backend = path.join(repository, "target", "debug", "lovelyhawk-backend.exe");
const which = process.env.LAB ?? "ubuntu";
if (!isLinuxLab(which)) throw new Error("This probe requires a defined Linux lab target.");
const container = `lab-${which}`;
const port = 9333;
const runId = randomUUID();
const fixtureDirectory = `/usr/local/lib/lovelyres-probe-${runId}`;
const fixture = `${fixtureDirectory}/.evidence-sample`;
const checks = [];
const consoleErrors = [];

let failures = 0;
function check(name, actual, expected = true) {
  const ok = actual === expected;
  checks.push({ name, passed: ok });
  if (!ok) failures += 1;
  console.log(`  ${ok ? "PASS" : "FAIL"} ${name}${ok ? "" : `\n       expected ${JSON.stringify(expected)}\n       actual   ${JSON.stringify(actual)}`}`);
}

function onHost(command) {
  return execFileSync(
    "wsl.exe",
    ["-d", "Ubuntu", "-u", "root", "--", "docker", "exec", container, "sh", "-c", command],
    { encoding: "utf8", windowsHide: true, timeout: 30_000 },
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

const evidence = path.join(repository, "target", "lab-ui", `emergency-${which}-${runId}`);
fs.mkdirSync(evidence, { recursive: true });

/** Saves what the operator would be looking at, as evidence for the change. */
async function shot(session, name) {
  const { data } = await session.send("Page.captureScreenshot", { format: "png" });
  const file = path.join(evidence, `${name}.png`);
  fs.writeFileSync(file, Buffer.from(data, "base64"));
  console.log(`      saved ${file}`);
}

const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "lovelyhawk-ui-"));
let app;
let session;
let fixtureCreated = false;
try {
  const identity = execFileSync("wsl.exe", [
    "-d", "Ubuntu", "-u", "root", "--", "docker", "inspect", "--format",
    '{{.Config.Image}}|{{.HostConfig.Privileged}}|{{len .Mounts}}', container,
  ], { encoding: "utf8", windowsHide: true, timeout: 30_000 }).trim();
  if (identity !== `lovelyres-lab:${which}|false|0`) throw new Error("The selected target is not an isolated, mount-free LovelyHawk lab.");
  onHost(`mkdir '${fixtureDirectory}'`);
  fixtureCreated = true;
  onHost(`printf '#!/bin/sh\\nexit 0\\n' > '${fixture}' && chmod 4755 '${fixture}'`);

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
  app = await startDesktop({
    dataRoot,
    port,
    onConsoleError: (entry) => {
      if (consoleErrors.length < 20) consoleErrors.push(JSON.stringify(entry.params).slice(0, 2_000));
    },
  });
  session = app.session;
  await waitFor(session, "document.querySelector('.connection-card') !== null", "the connection list");

  // --- connect from the window itself
  await session.evaluate(`(() => {
    const card = document.querySelector('.connection-card');
    card?.querySelector('button')?.click();
    return true;
  })()`);
  await waitFor(
    session,
    "document.querySelector('[data-testid=\"disconnect-target\"]:not([disabled])') !== null",
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
      planted: actionable.some(line => line.textContent.includes(${JSON.stringify(fixture)})),
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
      .find(candidate => candidate.textContent.includes(${JSON.stringify(fixture)}));
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
  check("the menu names the file the line named", menu.path, fixture);
  // 下载留证 joined the menu on 2026-09-08; the other three are the original actions.
  check("the menu offers evidence download, properties, remove-execute and quarantine",
    JSON.stringify(menu.items.map((item) => ["下载留证", "查看属性", "去掉执行权限", "隔离"].find((label) => item.startsWith(label)) ?? item)),
    JSON.stringify(["下载留证", "查看属性", "去掉执行权限", "隔离"]));
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
  check("and they are about the file that was clicked", properties.path, fixture);
  check("permission copy does not promise that everyone can run the file", !properties.text.includes("任何人都跑得起来"));
  await shot(session, "file-properties");
  await session.evaluate(`(() => {
    [...document.querySelectorAll('[data-testid="emergency-path-properties"] footer button')]
      .find(button => button.textContent.includes('关闭')).click();
    return true;
  })()`);

  // --- then the change, which has to be planned, confirmed and verified
  check("the target is untouched so far", onHost(`stat -c %a '${fixture}'`), "4755");
  await session.evaluate(`(() => {
    const line = [...document.querySelectorAll('.emergency-command-output pre span.has-path')]
      .find(candidate => candidate.textContent.includes(${JSON.stringify(fixture)}));
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
  check("the plan says what it will do", planned.includes("权限从 4755 改成 0644"));
  check("and how to undo it", planned.includes("恢复成读到的那组权限位"));
  check("nothing ran while the plan was on screen",
    onHost(`stat -c %a '${fixture}'`), "4755");

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
    onHost(`stat -c %a '${fixture}'`), "644");
  check("the file is still there to examine",
    onHost(`test -f '${fixture}' && echo yes`), "yes");

  // --- a verified action can be put back once, after an explicit second look
  check("the receipt offers to undo it",
    await session.evaluate("document.querySelector('[data-testid=\"emergency-path-undo\"]:not([disabled])') !== null"));
  await session.evaluate("document.querySelector('[data-testid=\"emergency-path-undo\"]').click(), true");
  await waitFor(session, "document.querySelector('[data-testid=\"emergency-path-undo-ask\"]') !== null", "the undo question");
  const asking = await session.evaluate(`(() => ({
    text: document.querySelector('[data-testid="emergency-path-undo-ask"]').textContent,
    focused: document.activeElement?.textContent ?? null,
  }))()`);
  console.log(`\nundo question:\n      ${asking.text.replace(/\s+/gu, " ").slice(0, 200)}`);
  await shot(session, "undo-question");
  check("the question says the file can run again", asking.text.includes("这个文件会重新可以执行"));
  check("the safe answer holds focus", asking.focused, "不撤销");
  check("asking changed nothing on the target", onHost(`stat -c %a '${fixture}'`), "644");
  await session.evaluate("document.querySelector('[data-testid=\"emergency-path-undo-confirm\"]').click(), true");
  await waitFor(session, "document.querySelector('[data-testid=\"emergency-path-undo-result\"]') !== null", "the undo result", 120);
  const undone = await session.evaluate(
    "document.querySelector('[data-testid=\"emergency-path-undo-result\"]').textContent",
  );
  console.log(`\nundo shown to the operator:\n      ${undone.replace(/\s+/gu, " ").slice(0, 160)}`);
  await shot(session, "undo-result");
  check("the window reports the undo verified",
    undone.startsWith("已撤销。") && undone.includes("权限已恢复为 4755，并在目标机上核对过"));
  check("and the target has its bits back", onHost(`stat -c %a '${fixture}'`), "4755");
  check("the undo is not offered a second time",
    await session.evaluate("document.querySelector('[data-testid=\"emergency-path-undo\"]') === null"));
  check("focus comes back to the dialog, not the page behind it",
    await session.evaluate("document.activeElement?.textContent?.trim() ?? null"), "关闭");

  // SUID alone must not be described as execute permission. Ask the actual
  // sidecar again through the properties UI, using the existing file offer.
  await session.evaluate("document.querySelector('[data-testid=\"emergency-path-dialog\"] footer button').click(), true");
  onHost(`chmod 4644 '${fixture}'`);
  await session.evaluate(`(() => {
    const line = [...document.querySelectorAll('.emergency-command-output pre span.has-path')]
      .find(candidate => candidate.textContent.includes(${JSON.stringify(fixture)}));
    line.dispatchEvent(new MouseEvent('contextmenu', {
      bubbles: true, cancelable: true, clientX: 200, clientY: 200
    }));
    return true;
  })()`);
  await waitFor(session, "document.querySelector('.emergency-path-menu') !== null", "the refreshed file menu");
  await session.evaluate(`(() => {
    [...document.querySelectorAll('.emergency-path-menu button')]
      .find(button => button.textContent.includes('查看属性')).click();
    return true;
  })()`);
  await waitFor(session, "document.querySelector('[data-testid=\"emergency-path-properties\"] dl') !== null", "refreshed permissions");
  const privilegeOnly = await session.evaluate("document.querySelector('[data-testid=\"emergency-path-properties\"]').textContent");
  check("SUID without execute bits is reported accurately", privilegeOnly.includes("4644（rwSr--r--）") && privilegeOnly.includes("未设置执行位"));
  await shot(session, "privilege-without-execute");
  await session.evaluate("document.querySelector('[data-testid=\"emergency-path-properties\"] footer button').click(), true");

  // Keep this page mounted while the target disappears. A hook below the
  // disconnected early return used to crash this exact transition.
  await session.evaluate("document.querySelector('[data-testid=\"disconnect-target\"]').click(), true");
  await waitFor(session, "document.querySelector('.emergency-commands-disconnected') !== null", "the disconnected workbench");
  check("disconnect keeps an actionable page on screen", await session.evaluate("document.querySelector('.emergency-commands-disconnected').textContent.includes('连接 SSH 目标后')"));
  check("disconnect removes file dialogs and menus", await session.evaluate("document.querySelector('.emergency-path-menu, .emergency-path-dialog') === null"));
  await shot(session, "disconnected-workbench");
  check("the desktop page reported no errors", consoleErrors.length, 0);

  console.log(`\n${failures === 0 ? "ALL CHECKS PASSED" : `${failures} CHECK(S) FAILED`}`);
  process.exitCode = failures === 0 ? 0 : 1;
} catch (error) {
  console.log(`\nFAILED: ${error.message}`);
  process.exitCode = 1;
} finally {
  fs.writeFileSync(path.join(evidence, "report.json"), `${JSON.stringify({
    schema: "lovelyres-emergency-ui/v1", generatedAt: new Date().toISOString(),
    target: { lab: which, container }, status: process.exitCode === 0 ? "PASS" : "FAIL",
    checks, consoleErrors,
  }, null, 2)}\n`);
  console.log(`evidence: ${evidence}`);
  await app?.close();
  if (fixtureCreated) onHost(`rm -f '${fixture}' && rmdir '${fixtureDirectory}'`);
  if (path.dirname(dataRoot) === os.tmpdir() && !fs.lstatSync(dataRoot).isSymbolicLink()) {
    fs.rmSync(dataRoot, { recursive: true, force: true, maxRetries: 10, retryDelay: 300 });
  }
}
