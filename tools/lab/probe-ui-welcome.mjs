// The welcome page in the real Tauri window: the product, the start card and
// the saved connections beside it, at a wide and a narrow window, light and
// dark. No lab host is needed; connections are saved through the connection
// manager into an isolated data root and never connected to.
//
//   node tools/lab/probe-ui-welcome.mjs

import { randomUUID } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { startDesktop } from "./desktop.mjs";

const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const runId = randomUUID();
const evidence = path.join(repository, "target", "lab-welcome", runId);
fs.mkdirSync(evidence, { recursive: true });
const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "lovelyhawk-welcome-"));
const checks = [];
let failures = 0;
let app = null;

function check(label, ok, detail = null) {
  checks.push({ label, passed: Boolean(ok), detail });
  if (!ok) failures += 1;
  console.log(`${ok ? "PASS" : "FAIL"} ${label}${ok || detail === null ? "" : ` — ${JSON.stringify(detail).slice(0, 500)}`}`);
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

const layout = `(() => {
  const rect = (selector) => { const r = document.querySelector(selector)?.getBoundingClientRect(); return r ? { left: r.left, right: r.right, top: r.top, bottom: r.bottom, width: r.width } : null; };
  const logo = document.querySelector('.welcome-hero-logo');
  return {
    title: document.querySelector('.welcome-hero-title')?.textContent ?? null,
    subtitle: document.querySelector('.welcome-hero-subtitle')?.textContent ?? null,
    logo: logo ? { loaded: logo.complete && logo.naturalWidth > 0, natural: logo.naturalWidth, shown: logo.getBoundingClientRect().width } : null,
    start: rect('.welcome-start'),
    recent: rect('.welcome-recent'),
    heading: document.querySelector('#welcome-intro-title')?.textContent ?? null,
    systems: [...document.querySelectorAll('.welcome-systems li')].map((item) => item.textContent),
    create: document.querySelector('.welcome-create-button')?.textContent.trim() ?? null,
    empty: document.querySelector('.welcome-recent .empty-state')?.textContent ?? null,
    rows: [...document.querySelectorAll('.welcome-connection-list .connection-card')].map((row) => ({
      name: row.querySelector('strong')?.textContent ?? null,
      target: row.querySelector('div > span')?.textContent ?? null,
      last: row.querySelector('small')?.textContent ?? null,
      actions: [...row.querySelectorAll('button')].map((button) => button.getAttribute('aria-label')),
      nameClipped: (() => { const s = row.querySelector('strong'); return s ? getComputedStyle(s).textOverflow === 'ellipsis' : false; })(),
    })),
    flow: document.querySelectorAll('.welcome-flow').length,
    tools: document.querySelectorAll('.welcome-tool').length,
    toolHeights: [...document.querySelectorAll('.welcome-tool')].map((tool) => Math.round(tool.getBoundingClientRect().height)),
    toolRows: new Set([...document.querySelectorAll('.welcome-tool')].map((tool) => Math.round(tool.getBoundingClientRect().top))).size,
    sidebar: getComputedStyle(document.querySelector('.sidebar')).display,
    content: rect('.workspace'),
    viewport: window.innerWidth,
    overflowX: document.querySelector('.welcome-page')?.scrollWidth > document.querySelector('.welcome-page')?.clientWidth + 1,
  };
})()`;

try {
  const consoleErrors = [];
  app = await startDesktop({ dataRoot, evidence,
    onConsoleError: (event) => consoleErrors.push(JSON.stringify(event.params ?? event).slice(0, 600)) });
  const page = app.session;
  const evaluate = (expression) => page.evaluate(expression);
  await until(() => evaluate("document.querySelector('[data-testid=\"welcome-view\"]') !== null"), "the welcome view", 60_000);
  await app.setViewport(1440, 900);
  await until(() => evaluate("document.querySelector('.welcome-hero-logo')?.complete === true"), "the logo");
  await sleep(300);

  // 1. First launch: the product, the start card beside an empty list.
  let now = await evaluate(layout);
  check("the welcome page opens with the logo, the name and what the product is for",
    now.logo?.loaded === true && now.logo.natural === 1254 && now.logo.shown >= 60 &&
    now.title === "LovelyHawk." && now.subtitle === "Linux 应急响应 / 运维工作台", now);
  check("starting a response and the saved connections sit side by side in a wide window",
    now.start !== null && now.recent !== null && now.start.right < now.recent.left &&
    Math.abs(now.start.top - now.recent.top) < 2 && now.start.width > now.recent.width, { start: now.start, recent: now.recent });
  check("the start card says what to do first, which systems are recognised, and offers 新建连接",
    now.heading === "开始一次应急响应" && now.systems.length === 12 && now.systems.includes("openEuler") &&
    now.create === "新建连接", now);
  check("with nothing saved the list says so instead of looking broken",
    (now.empty ?? "").includes("还没有保存任何连接") && now.rows.length === 0 && !now.overflowX, now);
  check("the start screen has no sidebar and no step-by-step route: the cards span the window",
    now.sidebar === "none" && now.flow === 0 && now.content !== null && now.content.left <= 1 && now.content.width >= now.viewport - 2,
    { sidebar: now.sidebar, flow: now.flow, content: now.content });
  check("the tools that need no target are one row of small buttons",
    now.tools >= 4 && now.toolHeights.every((height) => height <= 36) && now.toolRows === 1, { heights: now.toolHeights, rows: now.toolRows });
  await page.shot("welcome-empty.png");

  // 2. Two saved connections, created through the connection manager.
  await evaluate("document.querySelector('.welcome-create-button').click(), true");
  for (const [index, entry] of [["实验 A", "192.0.2.10"], ["实验 B", "192.0.2.11"]].entries()) {
    if (index > 0) {
      await evaluate("[...document.querySelectorAll('.connection-manager-header button')].find((b) => b.textContent.trim() === '新建连接').click(), true");
    }
    await until(() => evaluate("document.querySelector('.connection-editor') !== null"), "the connection editor");
    await evaluate(`(() => {
      const set = (label, value) => {
        const field = [...document.querySelectorAll('.connection-editor .connection-field')].find((candidate) => candidate.querySelector('span')?.textContent.startsWith(label));
        const input = field?.querySelector('input, textarea');
        Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(input, value);
        input.dispatchEvent(new Event('input', { bubbles: true }));
      };
      set('连接名称', ${JSON.stringify(entry[0])});
      set('主机名或 IP', ${JSON.stringify(entry[1])});
      [...document.querySelectorAll('.connection-editor .auth-picker button')].find((b) => b.textContent.trim() === '交互认证 / MFA').click();
      return true;
    })()`);
    await sleep(150);
    await evaluate("document.querySelector('.connection-editor button[type=\"submit\"]').click(), true");
    await until(() => evaluate(`document.querySelector('.connection-details-view h2')?.textContent === ${JSON.stringify(entry[0])}`), `saving ${entry[0]}`);
  }
  await evaluate("document.querySelector('[aria-label=\"关闭连接管理\"]').click(), true");
  await until(async () => (await evaluate(layout)).rows.length === 2, "the two rows");
  now = await evaluate(layout);
  check("saved connections appear in the card with their target, when last used, and connect / settings / delete",
    now.rows.map((row) => row.name).join(",") === "实验 A,实验 B" &&
    now.rows[0].target.endsWith("@192.0.2.10:22") && now.rows.every((row) => row.last === "还没有连接过") &&
    now.rows[0].actions.join(",") === "连接 实验 A,设置 实验 A,删除 实验 A" && now.rows.every((row) => row.nameClipped), now.rows);
  await page.shot("welcome-connections.png");

  // 3. 设置 opens that connection in the manager, then back.
  await evaluate("document.querySelector('[aria-label=\"设置 实验 B\"]').click(), true");
  await until(() => evaluate("document.querySelector('.connection-editor') !== null || document.querySelector('.connection-details-view h2')?.textContent === '实验 B'"), "the manager on 实验 B");
  check("设置 on a row opens that connection in the connection manager",
    (await evaluate("document.querySelector('.connection-manager')?.textContent.includes('实验 B') === true")));
  await evaluate("document.querySelector('[aria-label=\"关闭连接管理\"]')?.click(), true");
  await sleep(300);

  // 4. The smallest window: the cards stack, nothing scrolls sideways.
  await app.setViewport(1080, 700);
  await sleep(300);
  now = await evaluate(layout);
  check("in the smallest window both cards still sit side by side and nothing scrolls sideways",
    now.start !== null && now.recent !== null && now.start.right < now.recent.left && !now.overflowX,
    { start: now.start, recent: now.recent, overflowX: now.overflowX });
  await page.shot("welcome-narrow.png");
  const centred = () => evaluate(`(() => {
    const content = document.querySelector('.content').getBoundingClientRect();
    const inner = document.querySelector('.welcome-inner').getBoundingClientRect();
    return { above: Math.round(inner.top - content.top), below: Math.round(content.bottom - inner.bottom),
      left: Math.round(inner.left - content.left), right: Math.round(content.right - inner.right),
      scrollTop: document.querySelector('.content').scrollTop };
  })()`);
  const small = await centred();
  check("in the smallest window the top of the start screen is still in view, and the rest scrolls",
    small.above >= 0 && small.scrollTop === 0, small);

  // 4a. A large window: the start screen sits in the middle, not at the top.
  await app.setViewport(1920, 1080);
  await sleep(400);
  const big = await centred();
  check("in a large window the start screen is centred both ways, a little above the middle",
    big.above >= 80 && big.below >= 80 && big.below - big.above >= 0 && big.below - big.above <= 60 &&
    Math.abs(big.left - big.right) <= 2, big);
  await page.shot("welcome-1080p.png");

  // 4b. Leaving the start screen brings the sidebar back.
  await evaluate("document.querySelector('[data-testid=\"welcome-tool-security-reference\"]').click(), true");
  await until(() => evaluate("document.querySelector('[data-testid=\"welcome-view\"]') === null"), "the security reference");
  await sleep(200);
  check("opening a tool from the start screen brings the sidebar back for every other page",
    (await evaluate("getComputedStyle(document.querySelector('.sidebar')).display")) !== "none" &&
    (await evaluate("[...document.querySelectorAll('.nav-item')].some((item) => item.classList.contains('active') && item.textContent.includes('安全速查'))")));

  // 5. Dark theme.
  await app.setViewport(1440, 900);
  await evaluate("document.documentElement.dataset.theme = 'dark', true");
  await sleep(300);
  await page.shot("welcome-dark.png");
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
  schema: "lovelyhawk-welcome-probe/v1",
  status: failures === 0 ? "PASS" : "FAIL",
  generatedAt: new Date().toISOString(),
  checks,
}, null, 2)}\n`);
console.log(`${failures === 0 ? "PASS" : "FAIL"}: ${checks.filter((item) => item.passed).length}/${checks.length}; evidence in ${evidence}`);
process.exitCode = failures === 0 ? 0 : 1;
