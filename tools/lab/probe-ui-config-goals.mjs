// The configuration generator's goal search and typed database assignments
// in the real Tauri window, each check named after the GPUI test it replaces
// (docs/CONFIG_GENERATOR_TEST_BACKLOG.md, `desktop-cdp::config-generator::…`).
// Sentences are typed into the generator's own search box and the visual
// editor's own assignment box; every answer comes from core's reviewed
// catalogue through the backend. The save dialog is answered by the debug
// build's test hook; the file written is read back here. No lab host is needed.
//
//   node tools/lab/probe-ui-config-goals.mjs

import { randomUUID } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { startDesktop } from "./desktop.mjs";

const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const evidence = path.join(repository, "target", "lab-config-goals", randomUUID());
const files = path.join(evidence, "files");
fs.mkdirSync(files, { recursive: true });
const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "lovelyhawk-config-goals-"));
const checks = [];
let failures = 0;
let app = null;

function check(id, ok, detail = null) {
  checks.push({ id: `desktop-cdp::config-generator::${id}`, passed: Boolean(ok), detail });
  if (!ok) failures += 1;
  console.log(`${ok ? "PASS" : "FAIL"} ${id}${ok || detail === null ? "" : ` — ${JSON.stringify(detail).slice(0, 900)}`}`);
}
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
async function until(predicate, label, timeoutMs = 30_000) {
  const end = Date.now() + timeoutMs;
  while (Date.now() < end) {
    try { if (await predicate()) return; } catch {}
    await sleep(150);
  }
  throw new Error(`Timed out: ${label}`);
}

try {
  const consoleErrors = [];
  app = await startDesktop({ dataRoot, evidence, dialogAnswers: [], clipboard: true,
    onConsoleError: (event) => consoleErrors.push(JSON.stringify(event.params ?? event).slice(0, 600)) });
  const page = app.session;
  const evaluate = (expression) => page.evaluate(expression);
  const uiWait = (expression, label, timeoutMs) => until(async () => (await evaluate(expression)) === true, label, timeoutMs);
  const q = (selector) => JSON.stringify(selector);
  const exists = (selector) => evaluate(`document.querySelector(${q(selector)}) !== null`);
  const textOf = (selector) => evaluate(`document.querySelector(${q(selector)})?.textContent ?? ''`);
  const valueOf = (selector) => evaluate(`document.querySelector(${q(selector)})?.value ?? null`);
  const click = (selector) => evaluate(`(() => { const el = document.querySelector(${q(selector)}); if (!el) throw new Error('missing ' + ${q(selector)}); el.click(); return true; })()`);
  const clickText = (selector, text) => evaluate(`(() => { const b = [...document.querySelectorAll(${q(selector)})].find((x) => x.textContent.trim().startsWith(${q(text)}) && !x.disabled); if (!b) throw new Error('missing ' + ${q(text)}); b.click(); return true; })()`);
  const setValue = (selector, value) => evaluate(`(() => { const el = document.querySelector(${q(selector)}); if (!el) throw new Error('missing ' + ${q(selector)}); Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(el, ${q(value)}); el.dispatchEvent(new Event('input', { bubbles: true })); return true; })()`);
  const pick = (selector, value) => evaluate(`(() => { const el = document.querySelector(${q(selector)}); if (!el) throw new Error('no ' + ${q(selector)}); Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, 'value').set.call(el, ${q(value)}); el.dispatchEvent(new Event('change', { bubbles: true })); return true; })()`);
  const mode = () => textOf(".configuration-modes button[aria-pressed=\"true\"]");
  const status = () => evaluate("(() => { const s = document.querySelector('[data-testid=\"config-visual-status\"]'); return s ? { file: s.querySelector('strong')?.textContent ?? '', source: s.querySelector('span')?.textContent ?? '', dirty: document.querySelector('[data-testid=\"config-visual-dirty\"]') !== null } : null; })()");
  const preview = () => evaluate("document.querySelector('[data-testid=\"config-visual-preview\"] pre')?.textContent ?? null");
  const dialogTitle = () => evaluate("document.querySelector('.dialog-host #dialog-host-title')?.textContent ?? null");
  const SEARCH = ".config-search input[type=search]";
  const GOALS = "[data-testid=\"config-goal-results\"]";

  async function toGenerator() {
    await clickText(".configuration-modes button", "生成新配置");
    await uiWait(`document.querySelector(${q(SEARCH)}) !== null`, "the generator");
  }
  /** Types a sentence into the generator's search and waits for the goal answer. */
  async function search(sentence, ready) {
    await setValue(SEARCH, sentence);
    // The search waits a quarter second after typing; see it start before reading its answer.
    await uiWait(`document.querySelector(${q(GOALS)})?.textContent.includes('正在按目标查找') ?? false`, `the search for ${sentence} to start`, 5_000);
    await uiWait(`document.querySelector(${q(GOALS)}) !== null && !document.querySelector(${q(GOALS)}).textContent.includes('正在按目标查找') && document.querySelector(${q(ready)}) !== null`, `goals for ${sentence}`);
    await sleep(150);
  }

  await uiWait("document.querySelector('.nav-item') !== null", "the main window", 60_000);
  await app.setViewport(1600, 1000);
  await evaluate("[...document.querySelectorAll('.nav-item')].find((n) => n.querySelector('strong')?.textContent === '配置')?.click(), true");
  await uiWait("document.querySelector('.configuration-modes') !== null", "the configuration page");
  await toGenerator();

  // --- unified_goal_search_opens_database_guidance_and_explains_unavailable_products
  await search("PostgreSQL 允许数据库远程连接", "[data-testid=\"config-goal-database-bundles\"]");
  const bundles = await evaluate(`[...document.querySelectorAll('[data-testid="config-goal-database-bundles"] > ul > li')].map((li) => ({
    title: li.querySelector('strong')?.textContent ?? '', where: li.querySelector('span')?.textContent ?? '',
    steps: [...li.querySelectorAll('.config-goal-steps li')].map((step) => step.querySelector('span')?.textContent ?? ''),
    missing: li.textContent.includes('必需步骤不能只靠这个文件完成'), gap: li.querySelector('.config-goal-gap strong')?.textContent ?? null }))`);
  await page.shot("goal-database-bundle.png");
  await search("PostgreSQL 提高最大连接数", "[data-testid=\"config-goal-database-parameters\"]");
  const parameterRow = await evaluate(`(() => { const li = [...document.querySelectorAll('[data-testid="config-goal-database-parameters"] > ul > li')].find((x) => x.querySelector('strong')?.textContent === 'max_connections'); return li ? { where: li.querySelector('span').textContent, buttons: [...li.querySelectorAll('button')].map((b) => b.textContent) } : null; })()`);
  await evaluate(`[...document.querySelectorAll('[data-testid="config-goal-database-parameters"] > ul > li')].find((x) => x.querySelector('strong')?.textContent === 'max_connections').querySelector('[data-testid="config-goal-open-parameter"]').click(), true`);
  await uiWait("document.querySelector('[data-testid=\"config-visual-status\"]') !== null", "the parameter in the visual editor");
  await uiWait("document.querySelector('[data-testid=\"config-visual-parameter-detail\"]') !== null", "the parameter selected");
  const openedParameter = {
    mode: await mode(), status: await status(),
    version: await evaluate("(() => { const s = document.querySelector('[data-testid=\"config-visual-schema\"]'); return s?.selectedOptions[0]?.textContent ?? null; })()"),
    search: await valueOf("[data-testid=\"config-visual-parameter-search\"]"),
    detail: await textOf("[data-testid=\"config-visual-parameter-detail\"]"),
  };
  await page.shot("goal-parameter-opened.png");
  await toGenerator();
  await search("MogDB", "[data-testid=\"config-goal-database-files\"]");
  const mogdbFiles = await evaluate(`[...document.querySelectorAll('[data-testid="config-goal-database-files"] > ul > li')].map((li) => ({ file: li.querySelector('strong').textContent, product: li.querySelector('span').textContent, opens: li.querySelector('[data-testid="config-goal-open-file"]') !== null }))`);
  await click("[data-testid=\"config-goal-open-file\"]");
  await uiWait("document.querySelector('[data-testid=\"config-visual-status\"] strong')?.textContent.startsWith('MogDB') ?? false", "the MogDB file");
  const openedFile = { mode: await mode(), status: await status() };
  // An unsaved edit is never set aside for a search result: leaving asks, and 取消 keeps it.
  await evaluate("[...document.querySelectorAll('[data-testid=\"config-visual-add\"] .config-visual-choice label')].find((l) => l.textContent.trim() === '注释').querySelector('input').click(), true");
  await setValue("[data-testid=\"config-visual-add\"] .config-visual-field input", "探针加的一行说明");
  await evaluate("document.querySelector('[data-testid=\"config-visual-add\"] button[type=submit]').click(), true");
  await until(async () => (await status())?.dirty === true, "the unsaved edit");
  const withEdit = await preview();
  await clickText(".configuration-modes button", "生成新配置");
  await until(async () => (await dialogTitle()) !== null, "the discard question");
  const askedToLeave = await dialogTitle();
  await clickText(".dialog-host button", "取消");
  await until(async () => (await dialogTitle()) === null, "the dialog to close");
  const keptEdit = { mode: await mode(), status: await status(), same: (await preview()) === withEdit };
  await clickText(".configuration-modes button", "生成新配置");
  await until(async () => (await dialogTitle()) !== null, "the discard question again");
  await clickText(".dialog-host button", "放弃修改");
  await uiWait(`document.querySelector(${q(SEARCH)}) !== null`, "the generator after giving the edit up");
  const gaps = {};
  for (const sentence of ["shentong-native", "Apache TLS", "PostgreSQL 15 max_connections"]) {
    await search(sentence, "[data-testid=\"config-goal-unavailable\"]");
    gaps[sentence] = await evaluate(`[...document.querySelectorAll('[data-testid="config-goal-unavailable"] > ul > li')].map((li) => li.textContent)`);
  }
  await page.shot("goal-unavailable.png");
  check("unified_goal_search_opens_database_guidance_and_explains_unavailable_products",
    bundles.length > 0 && bundles.every((bundle) => bundle.where.startsWith("PostgreSQL") && bundle.steps.some((step) => step.includes("listen_addresses")) &&
      bundle.steps.includes("在配置文件之外完成") && bundle.missing && bundle.gap !== null) &&
      parameterRow !== null && parameterRow.where.startsWith("PostgreSQL 1") && parameterRow.buttons.includes("写一条赋值") &&
      openedParameter.mode.includes("可视化编辑") && openedParameter.status?.file === "PostgreSQL · postgresql.conf" &&
      openedParameter.status?.source === "起始内容" && !openedParameter.status?.dirty &&
      (openedParameter.version ?? "").startsWith("PostgreSQL 1") && openedParameter.search === "max_connections" &&
      openedParameter.detail.includes("max_connections") && openedParameter.detail.includes("以上来自内置目录") &&
      mogdbFiles.length > 0 && mogdbFiles.every((file) => file.product.startsWith("MogDB")) && mogdbFiles[0].opens &&
      openedFile.mode.includes("可视化编辑") && !openedFile.status?.dirty &&
      askedToLeave === "放弃未另存的修改？" && keptEdit.mode.includes("可视化编辑") && keptEdit.status?.dirty && keptEdit.same &&
      gaps["shentong-native"].some((text) => text.includes("神通")) &&
      gaps["Apache TLS"].some((text) => text.startsWith("Apache httpd")) &&
      gaps["PostgreSQL 15 max_connections"].some((text) => text.startsWith("PostgreSQL") && text.includes("这个版本还没有收录")),
    { bundles, parameterRow, openedParameter: { ...openedParameter, detail: openedParameter.detail.slice(0, 80) }, mogdbFiles, openedFile,
      askedToLeave, keptEdit, gaps });

  // --- database_assignment_previews_then_atomically_confirms_a_typed_local_draft
  await search("PostgreSQL 16 @postgresql-main max_connections = 250", "[data-testid=\"config-goal-assignment-ready\"]");
  const ready = {
    title: await textOf("[data-testid=\"config-goal-assignment-ready\"] h3"),
    facts: await textOf("[data-testid=\"config-goal-assignment-ready\"] .config-goal-facts"),
    value: await valueOf("[data-testid=\"config-goal-assignment-value\"]"),
    landing: await textOf("[data-testid=\"config-goal-assignment-ready\"] .config-goal-hint"),
    // A resolved assignment is answered on its own: no fuzzy goals, no catalogue matches, no 403 card.
    others: await evaluate("['config-goal-database-parameters', 'config-goal-database-bundles', 'config-goal-recipes', 'config-forbidden-goal'].filter((id) => document.querySelector(`[data-testid=\"${id}\"]`) !== null).concat(document.querySelector('[aria-label=\"配置特性搜索结果\"]') ? ['catalogue'] : [])"),
    mode: await mode(),
  };
  await setValue("[data-testid=\"config-goal-assignment-value\"]", "300");
  await sleep(200);
  const edited = { value: await valueOf("[data-testid=\"config-goal-assignment-value\"]"), mode: await mode(),
    visual: await exists("[data-testid=\"config-visual-status\"]") };
  await page.shot("goal-assignment-ready.png");
  await click("[data-testid=\"config-goal-assignment-confirm\"]");
  await uiWait("document.querySelector('[data-testid=\"config-visual-status\"]') !== null", "the new draft in the visual editor");
  await uiWait("document.querySelector('[data-testid=\"config-visual-parameter-detail\"]') !== null", "the parameter selected");
  const landed = {
    mode: await mode(), status: await status(), text: await preview(),
    version: await evaluate("document.querySelector('[data-testid=\"config-visual-schema\"]')?.selectedOptions[0]?.textContent ?? null"),
    search: await valueOf("[data-testid=\"config-visual-parameter-search\"]"),
  };
  await page.shot("goal-assignment-landed.png");
  const savedPath = path.join(files, "postgresql.conf");
  app.setDialogAnswers([savedPath]);
  await clickText(".config-visual-toolbar button", "另存为文件");
  await until(() => fs.existsSync(savedPath), "the saved draft");
  await until(async () => (await status())?.dirty === false, "the unsaved mark to clear");
  check("database_assignment_previews_then_atomically_confirms_a_typed_local_draft",
    ready.title === "把 max_connections 写入 PostgreSQL 的 postgresql.conf" && ready.facts.startsWith("对照版本：PostgreSQL 16.x") &&
      ready.value === "250" && ready.landing.includes("新建一份只含这一项的草稿") && ready.others.length === 0 &&
      ready.mode.includes("生成新配置") && edited.value === "300" && edited.mode.includes("生成新配置") && !edited.visual &&
      landed.mode.includes("可视化编辑") && landed.status?.file === "PostgreSQL · postgresql.conf" &&
      landed.status?.source === "按赋值新建" && landed.status?.dirty && landed.text?.trim() === "max_connections = 300" &&
      (landed.version ?? "").startsWith("PostgreSQL 16.x") && landed.search === "max_connections" &&
      fs.readFileSync(savedPath, "utf8") === landed.text,
    { ready, edited, landed });

  // --- database_assignment_ambiguity_rejection_and_failed_stage_never_mutate_the_document
  await toGenerator();
  await search("MariaDB 11.4 @mariadb-option-file wait_timeout = 60", "[data-testid=\"config-goal-assignment-ambiguous\"]");
  const ambiguous = {
    candidates: await evaluate("[...document.querySelectorAll('[data-testid=\"config-goal-assignment-candidate\"]')].map((b) => b.querySelector('strong').textContent)"),
    valueShown: await exists("[data-testid=\"config-goal-assignment-value\"]"),
  };
  await evaluate("[...document.querySelectorAll('[data-testid=\"config-goal-assignment-candidate\"]')].find((b) => b.querySelector('strong').textContent === '[mysqld] wait_timeout').click(), true");
  await uiWait("document.querySelector('[data-testid=\"config-goal-assignment-ready\"]') !== null", "the chosen candidate");
  const chosen = { title: await textOf("[data-testid=\"config-goal-assignment-ready\"] h3"), value: await valueOf("[data-testid=\"config-goal-assignment-value\"]") };
  const refusals = {};
  for (const [sentence, expected] of [
    ["PostgreSQL 16 @postgresql-main max_connections = NeverEcho_X9NeverEcho_X9NeverEcho_X9", "不符合所选版本目录"],
    ["PostgreSQL 16 @postgresql-main max_connections 改成 NeverEcho_X9", "“改成”这类说法不会被当作赋值"],
  ]) {
    await search(sentence, "[data-testid=\"config-goal-assignment-blocked\"]");
    const card = await textOf(GOALS);
    refusals[expected] = { shown: card.includes(expected), echoed: card.includes("NeverEcho"),
      others: await evaluate("document.querySelector('[aria-label=\"配置特性搜索结果\"]') !== null || document.querySelector('[data-testid=\"config-goal-database-parameters\"]') !== null") };
  }
  await page.shot("goal-assignment-refused.png");
  // In the visual editor: a file that writes the parameter twice is blocked before confirming.
  await clickText(".configuration-modes button", "可视化编辑");
  await uiWait("document.querySelector('.config-visual-product') !== null", "the visual editor");
  await clickText(".config-visual-product button", "数据库配置文件");
  await uiWait("document.querySelector('[data-testid=\"config-visual-database-product\"]') !== null", "the database picker");
  await pick("[data-testid=\"config-visual-database-product\"]", "postgresql");
  await pick("[data-testid=\"config-visual-database-file\"]", "postgresql-main");
  const twicePath = path.join(files, "twice.conf");
  const twiceText = "max_connections = 100\nmax_connections = 200\n";
  fs.writeFileSync(twicePath, twiceText);
  app.setDialogAnswers([twicePath]);
  await clickText(".config-visual-toolbar button", "导入本地文件");
  await uiWait("document.querySelector('[data-testid=\"config-visual-status\"] span')?.textContent === '导入的文件'", "the imported file");
  const v16 = await evaluate("[...document.querySelectorAll('[data-testid=\"config-visual-schema\"] option')].find((o) => o.textContent.startsWith('PostgreSQL 16.x'))?.value ?? null");
  await pick("[data-testid=\"config-visual-schema\"]", v16);
  await uiWait("document.querySelector('[data-testid=\"config-goal-box\"]') !== null && document.querySelector('[data-testid=\"config-visual-parameters\"]') !== null", "version 16 and the assignment box");
  await setValue("[data-testid=\"config-goal-box-input\"]", "PostgreSQL 16 @postgresql-main max_connections = 300");
  await uiWait("document.querySelector('[data-testid=\"config-goal-box\"] [data-testid=\"config-goal-assignment-preflight-blocked\"]') !== null", "the duplicate blocked before confirming");
  const duplicate = {
    reason: await textOf("[data-testid=\"config-goal-box\"] [data-testid=\"config-goal-assignment-preflight-blocked\"]"),
    confirmOff: await evaluate("document.querySelector('[data-testid=\"config-goal-box\"] [data-testid=\"config-goal-assignment-confirm\"]').disabled"),
    same: (await preview()) === twiceText, status: await status(),
  };
  await page.shot("goal-assignment-duplicate.png");
  // A clean file of the same version: the value goes into it in place, once.
  await setValue("[data-testid=\"config-goal-box-input\"]", "");
  await clickText(".config-visual-toolbar button", "打开起始内容");
  await uiWait("document.querySelector('[data-testid=\"config-visual-status\"] span')?.textContent === '起始内容'", "the starter");
  const starterText = await preview();
  const v16again = await evaluate("[...document.querySelectorAll('[data-testid=\"config-visual-schema\"] option')].find((o) => o.textContent.startsWith('PostgreSQL 16.x'))?.value ?? null");
  await pick("[data-testid=\"config-visual-schema\"]", v16again);
  await uiWait("document.querySelector('[data-testid=\"config-visual-parameters\"]') !== null", "version 16 on the starter");
  // Unsaved edits read against another version: blocked, nothing changes.
  const v17 = await evaluate("[...document.querySelectorAll('[data-testid=\"config-visual-schema\"] option')].find((o) => o.textContent.startsWith('PostgreSQL 17.x'))?.value ?? null");
  await pick("[data-testid=\"config-visual-schema\"]", v17);
  await uiWait("(document.querySelector('[data-testid=\"config-visual-schema\"]')?.selectedOptions[0]?.textContent ?? '').startsWith('PostgreSQL 17.x')", "version 17");
  await setValue("[data-testid=\"config-visual-parameter-search\"]", "port");
  await sleep(200);
  await evaluate("[...document.querySelectorAll('.config-visual-parameter-list button')].find((b) => b.querySelector('.config-visual-parameter-key').textContent === 'port').click(), true");
  await uiWait("document.querySelector('[data-testid=\"config-visual-parameter-value\"]') !== null", "the port field");
  await setValue("[data-testid=\"config-visual-parameter-value\"]", "5433");
  await click("[data-testid=\"config-visual-parameter-apply\"]");
  await until(async () => (await preview())?.includes("port = 5433"), "the edit under 17");
  const dirty17 = await preview();
  await setValue("[data-testid=\"config-goal-box-input\"]", "PostgreSQL 16 @postgresql-main max_connections = 301");
  await uiWait("document.querySelector('[data-testid=\"config-goal-box\"] [data-testid=\"config-goal-assignment-preflight-blocked\"]') !== null", "the other version blocked");
  const otherVersion = {
    reason: await textOf("[data-testid=\"config-goal-box\"] [data-testid=\"config-goal-assignment-preflight-blocked\"]"),
    same: (await preview()) === dirty17, dirty: (await status())?.dirty,
  };
  // Back on 16 with the same edit unsaved: the value goes in place and the card is spent.
  await pick("[data-testid=\"config-visual-schema\"]", v16again);
  await uiWait("(document.querySelector('[data-testid=\"config-visual-schema\"]')?.selectedOptions[0]?.textContent ?? '').startsWith('PostgreSQL 16.x')", "version 16 again");
  await setValue("[data-testid=\"config-goal-box-input\"]", "PostgreSQL 16 @postgresql-main max_connections = 310");
  await uiWait("document.querySelector('[data-testid=\"config-goal-box\"] [data-testid=\"config-goal-assignment-ready\"]') !== null && !document.querySelector('[data-testid=\"config-goal-box\"] [data-testid=\"config-goal-assignment-confirm\"]').disabled", "a ready assignment for the open file");
  const inPlaceHint = await textOf("[data-testid=\"config-goal-box\"] [data-testid=\"config-goal-assignment-ready\"] .config-goal-hint");
  const beforeHandle = await textOf("[data-testid=\"config-visual-status\"] strong");
  await click("[data-testid=\"config-goal-box\"] [data-testid=\"config-goal-assignment-confirm\"]");
  await uiWait("document.querySelector('[data-testid=\"config-goal-box\"] [data-testid=\"config-goal-assignment-consumed\"]') !== null", "the spent card");
  const inPlace = { text: await preview(), status: await status(), notice: await textOf(".config-visual-notice") };
  await page.shot("goal-assignment-in-place.png");
  check("database_assignment_ambiguity_rejection_and_failed_stage_never_mutate_the_document",
    ambiguous.candidates.length >= 2 && ambiguous.candidates.includes("[mysqld] wait_timeout") && !ambiguous.valueShown &&
      chosen.title.startsWith("把 [mysqld] wait_timeout 写入 MariaDB") && chosen.value === "60" &&
      Object.values(refusals).every((refusal) => refusal.shown && !refusal.echoed && !refusal.others) &&
      duplicate.reason.includes("出现了多次") && duplicate.confirmOff && duplicate.same && !duplicate.status?.dirty &&
      otherVersion.reason.includes("对照的是另一个版本") && otherVersion.same && otherVersion.dirty &&
      inPlaceHint.includes("写进当前打开的文件") && beforeHandle === "PostgreSQL · postgresql.conf" &&
      inPlace.text?.includes("max_connections = 310") && inPlace.text?.includes("port = 5433") &&
      inPlace.text?.startsWith(starterText?.split("\n")[0] ?? "\u0000") &&
      (inPlace.text?.match(/max_connections/gu)?.length ?? 0) === 1 && inPlace.status?.dirty &&
      inPlace.notice.includes("已把 max_connections 写入当前文件"),
    { ambiguous, chosen, refusals, duplicate: { ...duplicate }, otherVersion, inPlaceHint, inPlace: { ...inPlace, text: inPlace.text?.slice(0, 300) } });
  check("no console errors", consoleErrors.length === 0, consoleErrors.slice(0, 2));
} catch (error) {
  failures += 1;
  console.log(`FAILED: ${error instanceof Error ? error.message : String(error)}`);
  try { await app?.session?.shot("failure.png"); } catch {}
} finally {
  try { await app?.close(); } catch {}
  // The window may still be letting go of its data folder; a leftover is
  // reported, never a reason to lose the report.
  try {
    fs.rmSync(dataRoot, { recursive: true, force: true, maxRetries: 20, retryDelay: 500 });
  } catch (error) {
    console.log(`note: could not remove ${dataRoot}: ${error instanceof Error ? error.message : String(error)}`);
  }
}
fs.writeFileSync(path.join(evidence, "report.json"), `${JSON.stringify({
  schema: "lovelyhawk-config-goals-probe/v1",
  status: failures === 0 ? "PASS" : "FAIL",
  generatedAt: new Date().toISOString(),
  checks,
}, null, 2)}\n`);
console.log(`${failures === 0 ? "PASS" : "FAIL"}: ${checks.filter((item) => item.passed).length}/${checks.length}; evidence in ${evidence}`);
process.exitCode = failures === 0 ? 0 : 1;
