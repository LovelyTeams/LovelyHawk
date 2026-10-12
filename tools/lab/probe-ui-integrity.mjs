// The file-integrity page end to end in the desktop window, on a lab host:
// a baseline recorded from a preset location after the window asks, a
// change planted on the host, a comparison that finds it, and the guarded
// file actions (quarantine and its undo, remove-execute) taken straight from
// the findings. A second baseline is started and cancelled. Only files this
// probe plants in its own directory under /usr/local/bin and the manifests it creates are touched,
// and both are removed by exact name at the end.
//
//   node tools/lab/probe-ui-integrity.mjs
//   LAB=alpine node tools/lab/probe-ui-integrity.mjs

import { execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { startDesktop } from "./desktop.mjs";
import { Sidecar, connect } from "./rpc-harness.mjs";
import { LAB_PORTS, labTarget } from "./lab-target.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const repository = path.resolve(here, "..", "..");
const backend = path.join(repository, "target", "debug", "lovelyhawk-backend.exe");
const which = process.env.LAB ?? "ubuntu";
if (!Object.hasOwn(LAB_PORTS, which)) throw new Error("This probe requires a defined Linux lab target.");
const container = `lab-${which}`;
const port = 9361;
const tag = randomUUID().slice(0, 8);
// Its own directory inside a preset location, so the preset baseline covers it.
const DIR = `/usr/local/bin/lh-probe-${tag}`;
const CHANGED = `${DIR}/changed`;
const ADDED = `${DIR}/added`;
const MANIFESTS = "/tmp/.lovelyres_fim";
const checks = [];
const consoleErrors = [];
let failures = 0;

function check(name, actual, expected = true) {
  const ok = typeof expected === "function" ? expected(actual) === true : actual === expected;
  checks.push({ name, passed: ok });
  if (!ok) failures += 1;
  console.log(`  ${ok ? "PASS" : "FAIL"} ${name}${ok ? "" : `\n       actual ${JSON.stringify(actual)}`}`);
}

function onHost(command) {
  return execFileSync(
    "wsl.exe",
    ["-d", "Ubuntu", "-u", "root", "--", "docker", "exec", container, "sh", "-c", command],
    { encoding: "utf8", windowsHide: true, timeout: 60_000 },
  ).split("\0").join("").trim();
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
async function waitFor(session, expression, label, attempts = 120) {
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    if (await session.evaluate(expression) === true) return;
    await sleep(500);
  }
  throw new Error(`timed out waiting for ${label}`);
}

const evidence = path.join(repository, "target", "lab-ui", `integrity-${which}-${tag}`);
fs.mkdirSync(evidence, { recursive: true });
async function shot(session, name) {
  const { data } = await session.send("Page.captureScreenshot", { format: "png" });
  fs.writeFileSync(path.join(evidence, `${name}.png`), Buffer.from(data, "base64"));
}

const manifests = () => onHost(`ls -1 ${MANIFESTS} 2>/dev/null || true`).split("\n").filter(Boolean);
const modeOf = (file) => onHost(`stat -c %a ${file} 2>/dev/null || echo gone`);
const clickText = (selector, text) => `(() => { const element = [...document.querySelectorAll(${JSON.stringify(selector)})].find((candidate) => candidate.textContent.trim() === ${JSON.stringify(text)}); if (!element || element.disabled) return false; element.click(); return true; })()`;
/** Ticks exactly the preset locations named, unticks the rest. */
const choosePresets = (paths) => `(() => {
  for (const label of document.querySelectorAll('.integrity-preset-grid label[data-preset-path]')) {
    const box = label.querySelector('input[type="checkbox"]');
    const wanted = ${JSON.stringify(paths)}.includes(label.dataset.presetPath ?? '');
    if (box.checked !== wanted) box.click();
  }
  return true;
})()`;
const findingFor = (file) => `[...document.querySelectorAll('.integrity-finding')].find((row) => row.querySelector('code')?.textContent === ${JSON.stringify(file)})`;

const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "lovelyhawk-ui-integrity-"));
const before = manifests();
let app;
let session;
try {
  const identity = execFileSync("wsl.exe", [
    "-d", "Ubuntu", "-u", "root", "--", "docker", "inspect", "--format",
    '{{.Config.Image}}|{{.HostConfig.Privileged}}|{{len .Mounts}}', container,
  ], { encoding: "utf8", windowsHide: true, timeout: 30_000 }).trim();
  if (identity !== `lovelyres-lab:${which}|false|0`) throw new Error("The selected target is not an isolated, mount-free LovelyHawk lab.");
  onHost(`mkdir -p ${DIR} && printf '#!/bin/sh\\necho original\\n' > ${CHANGED} && chmod 0755 ${CHANGED}`);

  const sidecar = new Sidecar(backend, dataRoot);
  try {
    const status = await connect(sidecar, labTarget(which));
    if (status.stage !== "connected") throw new Error(JSON.stringify(status));
  } finally {
    sidecar.close();
  }

  app = await startDesktop({
    dataRoot,
    port,
    onConsoleError: (entry) => {
      if (consoleErrors.length < 20) consoleErrors.push(JSON.stringify(entry.params).slice(0, 2_000));
    },
  });
  session = app.session;
  await waitFor(session, "document.querySelector('.connection-card') !== null", "the connection list");
  await session.evaluate("(() => { document.querySelector('.connection-card')?.querySelector('button')?.click(); return true; })()");
  await waitFor(session, "document.querySelector('[data-testid=\"disconnect-target\"]:not([disabled])') !== null", "the connected shell");
  await session.evaluate(clickText(".nav-item", "文件完整性"));
  await waitFor(session, "document.querySelector('.integrity-preset-grid input') !== null", "the preset locations");

  const page = await session.evaluate("document.querySelector('.integrity-page').textContent");
  check("the page explains itself without implementation words", page, (text) => text.includes("比较只读取文件") && !/Phase \d|只读比较/u.test(text));

  // --- record a baseline of /usr/local/bin only, after the window asks
  await session.evaluate(choosePresets([]));
  await waitFor(session, "document.querySelector('[data-testid=\"integrity-create\"]')?.disabled === true", "the create button to need a location");
  check("nothing can be created with no location chosen", await session.evaluate("document.querySelector('[data-testid=\"integrity-create\"]').disabled"), true);
  await session.evaluate(choosePresets(["/usr/local/bin"]));
  await waitFor(session, "document.querySelector('[data-testid=\"integrity-create\"]:not([disabled])') !== null", "the create button");
  await session.evaluate("document.querySelector('[data-testid=\"integrity-create\"]').click(), true");
  await waitFor(session, "document.querySelector('.dialog-host') !== null", "the confirmation");
  const question = await session.evaluate("document.querySelector('.dialog-host').textContent");
  await shot(session, "create-question");
  check("creating asks first, naming the location and where the manifest goes",
    question, (text) => text.includes("/usr/local/bin") && text.includes("/tmp/.lovelyres_fim") && text.includes("不会被改动"));
  check("nothing is written while it asks", manifests().length, before.length);
  await session.evaluate(clickText(".dialog-host button", "新建基线"));
  await waitFor(session, "document.querySelector('[data-testid=\"integrity-create-notice\"]') !== null", "the baseline", 240);
  const created = await session.evaluate("document.querySelector('[data-testid=\"integrity-create-notice\"]').textContent");
  check("the baseline is recorded and says how many files", created, (text) => /^基线已建立：记录了 \d+ 个文件（1 个位置）/u.test(text));
  check("one manifest was added on the host", manifests().length, before.length + 1);
  await waitFor(session, "document.querySelectorAll('.integrity-baseline-list button').length > 0", "the new baseline in the list");

  // --- change the host, then compare
  onHost(`printf 'echo tampered\\n' >> ${CHANGED} && printf '#!/bin/sh\\nid\\n' > ${ADDED} && chmod 4755 ${ADDED}`);
  await session.evaluate("document.querySelector('.integrity-baseline-list button')?.click(), true");
  await session.evaluate(clickText(".integrity-heading-actions button", "开始比较"));
  await waitFor(session, "document.querySelector('.integrity-findings') !== null", "the comparison", 240);
  const findings = await session.evaluate(`(() => [...document.querySelectorAll('.integrity-finding')].map((row) => ({
    path: row.querySelector('code')?.textContent ?? '',
    kind: row.className,
    action: row.querySelector('.integrity-finding-action') !== null,
  })))()`);
  await shot(session, "comparison");
  check("the comparison finds the added file, with file actions", findings, (rows) => rows.some((row) => row.path === ADDED && row.kind.includes("added") && row.action));
  check("and the changed one", findings, (rows) => rows.some((row) => row.path === CHANGED && row.kind.includes("modified") && row.action));

  // --- quarantine the added file from its finding, then undo
  await session.evaluate(`${findingFor(ADDED)}.querySelector('.integrity-finding-action').click(), true`);
  await waitFor(session, "document.querySelector('.emergency-path-menu') !== null", "the file menu");
  const menu = await session.evaluate("[...document.querySelectorAll('.emergency-path-menu button')].map((button) => button.textContent.trim())");
  check("the finding offers the same file actions as the command workbench", menu, (items) => ["下载留证", "查看属性", "去掉执行权限", "隔离"].every((label) => items.some((item) => item.startsWith(label))));
  await session.evaluate(`(() => { [...document.querySelectorAll('.emergency-path-menu button')].find((button) => button.textContent.startsWith('隔离')).click(); return true; })()`);
  await waitFor(session, "document.querySelector('[data-testid=\"emergency-path-execute\"]:not([disabled])') !== null", "the quarantine plan");
  check("nothing moved while the plan was on screen", modeOf(ADDED), "4755");
  await session.evaluate("document.querySelector('[data-testid=\"emergency-path-execute\"]').click(), true");
  await waitFor(session, "document.querySelector('[data-testid=\"emergency-path-dialog\"]')?.textContent.includes('目标机反馈') === true", "the quarantine receipt");
  const receipt = await session.evaluate("document.querySelector('[data-testid=\"emergency-path-dialog\"]').textContent");
  check("the quarantine is verified", receipt, (text) => text.includes("已完成，并在目标机上核对过。"));
  check("the file is gone from its place on the host", modeOf(ADDED), "gone");
  check("a copy is kept to put back", onHost(`ls ${DIR}/.lovelyres-backups 2>/dev/null | grep -c 'added' || true`), "1");
  await session.evaluate("document.querySelector('[data-testid=\"emergency-path-undo\"]').click(), true");
  await waitFor(session, "document.querySelector('[data-testid=\"emergency-path-undo-ask\"]') !== null", "the undo question");
  await session.evaluate("document.querySelector('[data-testid=\"emergency-path-undo-confirm\"]').click(), true");
  await waitFor(session, "document.querySelector('[data-testid=\"emergency-path-undo-result\"]') !== null", "the undo");
  check("undo puts it back as it was", modeOf(ADDED), "4755");
  await shot(session, "quarantine-undone");
  await session.evaluate(clickText("[data-testid=\"emergency-path-dialog\"] footer button", "关闭"));

  // --- remove execute from the changed file
  await session.evaluate(`${findingFor(CHANGED)}.querySelector('.integrity-finding-action').click(), true`);
  await waitFor(session, "document.querySelector('.emergency-path-menu') !== null", "the file menu again");
  await session.evaluate(`(() => { [...document.querySelectorAll('.emergency-path-menu button')].find((button) => button.textContent.startsWith('去掉执行权限')).click(); return true; })()`);
  await waitFor(session, "document.querySelector('[data-testid=\"emergency-path-execute\"]:not([disabled])') !== null", "the disarm plan");
  await session.evaluate("document.querySelector('[data-testid=\"emergency-path-execute\"]').click(), true");
  await waitFor(session, "document.querySelector('[data-testid=\"emergency-path-dialog\"]')?.textContent.includes('目标机反馈') === true", "the disarm receipt");
  check("the changed file can no longer run", modeOf(CHANGED), "644");
  await session.evaluate(clickText("[data-testid=\"emergency-path-dialog\"] footer button", "关闭"));

  // --- a second baseline, started and cancelled
  const beforeCancel = manifests().length;
  await session.evaluate(choosePresets(["/usr/bin", "/usr/sbin", "/bin", "/etc"]));
  await session.evaluate("document.querySelector('[data-testid=\"integrity-create\"]').click(), true");
  await waitFor(session, "document.querySelector('.dialog-host') !== null", "the second confirmation");
  await session.evaluate(clickText(".dialog-host button", "新建基线"));
  // Read in the same moment the cancel button is seen: a small host can
  // finish a moment later.
  const runningState = "(() => { const cancel = document.querySelector('[data-testid=\"integrity-create-cancel\"]:not([disabled])'); const text = document.querySelector('[data-testid=\"integrity-create-running\"]')?.textContent ?? null; return cancel !== null && text !== null ? text : null; })()";
  let running = null;
  for (let attempt = 0; attempt < 120 && running === null; attempt += 1) {
    running = await session.evaluate(runningState);
    if (running === null) await sleep(100);
  }
  check("a running creation says it is running and can be stopped", running, (text) => typeof text === "string" && text.startsWith("正在记录所选位置里的文件"));
  await session.evaluate("document.querySelector('[data-testid=\"integrity-create-cancel\"]')?.click(), true");
  await waitFor(session, "document.querySelector('[data-testid=\"integrity-create-notice\"]') !== null && document.querySelector('[data-testid=\"integrity-create-cancel\"]') === null", "the creation to stop", 240);
  const stopped = await session.evaluate("document.querySelector('[data-testid=\"integrity-create-notice\"]').textContent");
  // A fast host may finish first; then it is listed, which is also honest.
  check("cancelling stops it, or it reports it had already finished", stopped, (text) => text.startsWith("已取消新建基线") || text.startsWith("基线已建立"));
  console.log(`  second baseline: ${stopped}`);
  check("no unregistered manifest is left behind when it was cancelled", manifests().length, (count) => stopped.startsWith("基线已建立") ? count === beforeCancel + 1 : count <= beforeCancel + 1);

  check("the page reported no errors", consoleErrors.length, 0);
} catch (error) {
  console.log(`\nFAILED: ${error.message}`);
  failures += 1;
  if (session) await shot(session, "failure").catch(() => undefined);
} finally {
  fs.writeFileSync(path.join(evidence, "report.json"), `${JSON.stringify({
    schema: "lovelyhawk-integrity-ui/v1", generatedAt: new Date().toISOString(),
    target: { lab: which, container }, status: failures === 0 ? "PASS" : "FAIL", checks, consoleErrors,
  }, null, 2)}\n`);
  await app?.close();
  try {
    onHost(`rm -rf ${DIR}`);
    for (const name of manifests().filter((entry) => !before.includes(entry))) {
      if (/^[A-Za-z0-9._-]+$/u.test(name)) onHost(`rm -f ${MANIFESTS}/${name}`);
    }
  } catch {}
  if (path.dirname(dataRoot) === os.tmpdir()) fs.rmSync(dataRoot, { recursive: true, force: true, maxRetries: 10, retryDelay: 300 });
  console.log(`evidence: ${evidence}`);
}

console.log(`\n${failures === 0 ? "ALL CHECKS PASSED" : `${failures} CHECK(S) FAILED`}`);
process.exitCode = failures === 0 ? 0 : 1;
