// Every page at 1920 × 1080 in the real Tauri window: its content reaches the
// right-hand side of the window instead of stopping at a fixed width. The
// welcome screen is the one exception — it is centred on purpose.
//
//   node tools/lab/probe-ui-wide.mjs

import { randomUUID } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { startDesktop } from "./desktop.mjs";

const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const evidence = path.join(repository, "target", "lab-wide", randomUUID());
fs.mkdirSync(evidence, { recursive: true });
const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "lovelyhawk-wide-"));
const checks = [];
let failures = 0;
let app = null;
// The page's own padding plus a scrollbar: anything more is unused width.
const MAX_GAP = 48;

function check(label, ok, detail = null) {
  checks.push({ label, passed: Boolean(ok), detail });
  if (!ok) failures += 1;
  console.log(`${ok ? "PASS" : "FAIL"} ${label}${ok || detail === null ? "" : ` — ${JSON.stringify(detail).slice(0, 400)}`}`);
}
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
async function until(predicate, label, timeoutMs = 20_000) {
  const end = Date.now() + timeoutMs;
  while (Date.now() < end) {
    try { if (await predicate()) return; } catch {}
    await sleep(200);
  }
  throw new Error(`Timed out: ${label}`);
}

// How far the visible boxes in the page stay from the content area's left
// and right edges. A page that stops short on the right leaves a lopsided
// gap; a prompt deliberately centred (the "connect a target first" card)
// leaves the same space on both sides, and that is not unused width.
const measure = `(() => {
  const content = document.querySelector('.content');
  const box = content.getBoundingClientRect();
  let left = box.right;
  let right = box.left;
  for (const element of content.querySelectorAll('*')) {
    const rect = element.getBoundingClientRect();
    if (rect.width === 0 || rect.height === 0 || rect.top > box.bottom || rect.bottom < box.top) continue;
    if (getComputedStyle(element).visibility === 'hidden') continue;
    left = Math.min(left, Math.max(rect.left, box.left));
    right = Math.max(right, Math.min(rect.right, box.right));
  }
  const gap = Math.round(box.right - right);
  const leftGap = Math.round(left - box.left);
  return { gap, leftGap, centred: gap > ${MAX_GAP} && Math.abs(gap - leftGap) <= 12, width: Math.round(box.width) };
})()`;

try {
  const consoleErrors = [];
  app = await startDesktop({ dataRoot, evidence,
    onConsoleError: (event) => consoleErrors.push(JSON.stringify(event.params ?? event).slice(0, 600)) });
  const page = app.session;
  const evaluate = (expression) => page.evaluate(expression);
  await until(() => evaluate("document.querySelector('[data-testid=\"welcome-view\"]') !== null"), "the welcome view", 60_000);
  await app.setViewport(1920, 1080);
  await sleep(300);

  const titles = await evaluate("[...document.querySelectorAll('.nav-item')].map((item) => item.querySelector('strong').textContent)");
  for (const [index, title] of titles.entries()) {
    await evaluate(`document.querySelectorAll('.nav-item')[${index}].click(), true`);
    await until(() => evaluate(`document.querySelectorAll('.nav-item')[${index}].classList.contains('active')`), title);
    await sleep(500);
    if (title === "配置") {
      const modes = await evaluate("[...document.querySelectorAll('.configuration-modes button')].map((button) => button.querySelector('strong')?.textContent ?? button.textContent.trim())");
      for (const [modeIndex, mode] of modes.entries()) {
        await evaluate(`document.querySelectorAll('.configuration-modes button')[${modeIndex}].click(), true`);
        await sleep(700);
        const measured = await evaluate(measure);
        check(`配置 · ${mode} fills the window's width`, measured.gap <= MAX_GAP, measured);
        await page.shot(`config-${modeIndex}.png`);
      }
      continue;
    }
    const measured = await evaluate(measure);
    check(measured.centred ? `${title} shows a centred prompt, the same space on both sides` : `${title} fills the window's width`,
      measured.gap <= MAX_GAP || measured.centred, measured);
  }
  check("no console errors", consoleErrors.length === 0, consoleErrors.slice(0, 2));
} catch (error) {
  failures += 1;
  console.log(`FAILED: ${error instanceof Error ? error.message : String(error)}`);
  try { await app?.session?.shot("failure.png"); } catch {}
} finally {
  try { await app?.close(); } catch {}
  fs.rmSync(dataRoot, { recursive: true, force: true, maxRetries: 10, retryDelay: 300 });
}
fs.writeFileSync(path.join(evidence, "report.json"), `${JSON.stringify({
  schema: "lovelyhawk-wide-probe/v1",
  status: failures === 0 ? "PASS" : "FAIL",
  generatedAt: new Date().toISOString(),
  checks,
}, null, 2)}\n`);
console.log(`${failures === 0 ? "PASS" : "FAIL"}: ${checks.filter((item) => item.passed).length}/${checks.length}; evidence in ${evidence}`);
process.exitCode = failures === 0 ? 0 : 1;
