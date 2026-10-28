// The configuration generator's layout in the real Tauri window, measured the
// way the GPUI page's layout tests measured it: with the page area set to the
// sizes those tests drew (1200 × 800, 1200 × 600, 1200 × 420), reading the
// boxes the window actually laid out, and scrolling with real wheel input.
//
// Each check is named after the legacy test it replaces
// (docs/CONFIG_GENERATOR_TEST_BACKLOG.md, `desktop-cdp::config-generator::…`).
// No lab host is needed: the generator works on local drafts.
//
//   node tools/lab/probe-ui-config-layout.mjs

import { randomUUID } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { startDesktop } from "./desktop.mjs";

const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const evidence = path.join(repository, "target", "lab-config-layout", randomUUID());
fs.mkdirSync(evidence, { recursive: true });
const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "lovelyhawk-config-layout-"));
const checks = [];
let failures = 0;
let app = null;
// Layout boxes are fractional; half a pixel is "the same edge".
const EDGE = 0.5;

function check(id, ok, detail = null) {
  checks.push({ id: `desktop-cdp::config-generator::${id}`, passed: Boolean(ok), detail });
  if (!ok) failures += 1;
  console.log(`${ok ? "PASS" : "FAIL"} ${id}${detail === null ? "" : ` — ${JSON.stringify(detail).slice(0, 600)}`}`);
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
  app = await startDesktop({ dataRoot, evidence,
    onConsoleError: (event) => consoleErrors.push(JSON.stringify(event.params ?? event).slice(0, 600)) });
  const page = app.session;
  const evaluate = (expression) => page.evaluate(expression);
  const uiWait = (expression, label, timeoutMs) => until(async () => (await evaluate(expression)) === true, label, timeoutMs);
  const shot = async (name) => {
    const { data } = await page.send("Page.captureScreenshot", { format: "png" });
    fs.writeFileSync(path.join(evidence, `${name}.png`), Buffer.from(data, "base64"));
  };
  const rect = (selector) => evaluate(`(() => { const el = document.querySelector(${JSON.stringify(selector)}); if (!el) return null; const r = el.getBoundingClientRect(); return { left: r.left, top: r.top, right: r.right, bottom: r.bottom, width: r.width, height: r.height }; })()`);
  const scrollState = (selector) => evaluate(`(() => { const el = document.querySelector(${JSON.stringify(selector)}); return el ? { top: el.scrollTop, max: el.scrollHeight - el.clientHeight } : null; })()`);

  /** Sizes the window so the page area beside the sidebar is exactly width × height. */
  async function pageArea(width, height) {
    await app.setViewport(width + 400, height + 200);
    await sleep(250);
    const content = await rect(".content");
    await app.setViewport(Math.round(width + 400 - content.width + width), Math.round(height + 200 - content.height + height));
    await sleep(400);
    const actual = await rect(".content");
    if (Math.abs(actual.width - width) > 1 || Math.abs(actual.height - height) > 1) throw new Error(`page area is ${actual.width}×${actual.height}`);
  }
  /** A real wheel gesture at a point, as an operator's mouse would send it. */
  async function wheel(x, y, deltaY) {
    await page.send("Input.dispatchMouseEvent", { type: "mouseMoved", x, y });
    await page.send("Input.dispatchMouseEvent", { type: "mouseWheel", x, y, deltaX: 0, deltaY });
    await sleep(700);
  }
  async function product(title) {
    await evaluate(`(() => { const b = [...document.querySelectorAll('.config-product-list button')].find((x) => x.querySelector('strong')?.textContent === ${JSON.stringify(title)}); if (!b) throw new Error('no product ' + ${JSON.stringify(title)}); b.click(); return true; })()`);
    await uiWait(`document.querySelector('.config-section-heading h2')?.textContent === ${JSON.stringify(title)}`, title);
  }
  /** Selects a feature the way an operator does: enabling it opens its editor. */
  async function select(productKey, key) {
    const toggle = `[data-testid="config-feature-${productKey}-${key}"]`;
    const editor = `[data-testid="config-feature-inline-editor-${productKey}-${key}"]`;
    if (await evaluate(`document.querySelector('${editor}') !== null`)) return;
    if (await evaluate(`document.querySelector('${toggle}').checked`)) await evaluate(`document.querySelector('${toggle}').click(), true`);
    await evaluate(`document.querySelector('${toggle}').click(), true`);
    await uiWait(`document.querySelector('${editor}') !== null`, `${productKey} ${key} editor`);
    await evaluate(`document.querySelector('${editor}').scrollIntoView({ block: 'nearest' }), true`);
    await sleep(150);
  }
  /** The editor starts exactly where its row ends, as wide as the row, inside the editor column. */
  async function editorBelowRow(productKey, key) {
    const row = await rect(`[data-testid="config-feature-row-${productKey}-${key}"]`);
    const editor = await rect(`[data-testid="config-feature-inline-editor-${productKey}-${key}"]`);
    const column = await rect(".config-editor");
    const ok = row !== null && editor !== null &&
      Math.abs(editor.top - row.bottom) <= EDGE &&
      Math.abs(editor.left - row.left) <= EDGE && Math.abs(editor.width - row.width) <= EDGE &&
      editor.top >= column.top - EDGE && editor.bottom <= column.bottom + EDGE;
    return { ok, row, editor, column };
  }
  /** Product list, editor and preview side by side, top-aligned, inside the page. */
  async function threeColumns() {
    const content = await rect(".content");
    const products = await rect(".config-product-list");
    const editor = await rect(".config-editor");
    const preview = await rect(".config-preview");
    const ok = products !== null && editor !== null && preview !== null &&
      products.right <= editor.left + EDGE && editor.right <= preview.left + EDGE && preview.right <= content.right + EDGE &&
      Math.abs(products.top - editor.top) <= EDGE && Math.abs(editor.top - preview.top) <= EDGE;
    return { ok, products, editor, preview, content };
  }
  async function generate() {
    await evaluate("document.querySelector('[data-testid=\"config-generate\"]').click(), true");
    await uiWait("(document.querySelector('[data-testid=\"config-artifact-preview-text\"]')?.textContent ?? '').length > 0 && !document.querySelector('[data-testid=\"config-generate\"]').disabled", "the generated preview", 20_000)
      .catch(async (error) => {
        console.error(await evaluate("JSON.stringify({ notice: [...document.querySelectorAll('.config-generator-page [role=alert], .config-generator-page [role=status], .config-notice')].map((n) => n.textContent).join(' | '), invalid: [...document.querySelectorAll('.config-generator-page input:invalid')].map((i) => i.dataset.testid ?? i.name) })"));
        throw error;
      });
    await sleep(300);
  }
  /** Every checkbox of the selected product that the current choice allows, on. */
  async function enableAll(productKey, except = []) {
    await evaluate(`(() => {
      for (const box of document.querySelectorAll('input[data-testid^="config-feature-${productKey}-"]')) {
        const key = box.dataset.testid.slice('config-feature-${productKey}-'.length);
        if (box.disabled || ${JSON.stringify(except)}.includes(key)) continue;
        if (!box.checked) box.click();
      }
      return true;
    })()`);
    await sleep(200);
  }
  /** Exactly these features of the selected product on, every other one off. */
  async function enableOnly(productKey, keys) {
    await evaluate(`(() => {
      for (const box of document.querySelectorAll('input[data-testid^="config-feature-${productKey}-"]')) {
        const key = box.dataset.testid.slice('config-feature-${productKey}-'.length);
        const wanted = ${JSON.stringify(keys)}.includes(key);
        if (!box.disabled && box.checked !== wanted) box.click();
      }
      return true;
    })()`);
    await sleep(200);
  }
  /** Wheel over the preview text: it reaches its last line and nothing else moves. */
  async function previewScrollsAlone() {
    // Where an operator would put the pointer: on the part of the text that
    // is on screen, inside the preview column.
    await evaluate("document.querySelector('[data-testid=\"config-artifact-preview-text\"]').scrollIntoView({ block: 'nearest' }), true");
    await sleep(150);
    const pre = await evaluate(`(() => {
      const box = document.querySelector('[data-testid="config-artifact-preview-text"]').getBoundingClientRect();
      const column = document.querySelector('.config-preview').getBoundingClientRect();
      const top = Math.max(box.top, column.top, 0); const bottom = Math.min(box.bottom, column.bottom, window.innerHeight);
      return { left: box.left, width: box.width, top, height: bottom - top };
    })()`);
    const before = { page: await scrollState(".content"), editor: await scrollState(".config-editor") };
    const text = await scrollState('[data-testid="config-artifact-preview-text"]');
    await wheel(pre.left + pre.width / 2, pre.top + pre.height / 2, 5_000);
    const after = { text: await scrollState('[data-testid="config-artifact-preview-text"]'), page: await scrollState(".content"), editor: await scrollState(".config-editor") };
    // The last line is inside the text box and inside the preview column, so
    // it is actually on screen, not merely scrolled to inside a clipped box.
    const lastLineVisible = await evaluate(`(() => {
      const pre = document.querySelector('[data-testid="config-artifact-preview-text"]');
      const range = document.createRange(); range.selectNodeContents(pre);
      const lines = [...range.getClientRects()]; const box = pre.getBoundingClientRect();
      const column = document.querySelector('.config-preview').getBoundingClientRect();
      const last = lines[lines.length - 1];
      return last !== undefined && last.bottom <= Math.min(box.bottom, column.bottom) + 1 && last.top >= Math.max(box.top, column.top) - 1;
    })()`);
    return {
      ok: text.max > 0 && Math.abs(after.text.top - after.text.max) <= 1 && after.page.top === before.page.top && after.page.top === 0 &&
        after.editor.top === before.editor.top && lastLineVisible,
      overflow: text.max, after, before, lastLineVisible,
    };
  }

  await uiWait("document.querySelector('.nav-item') !== null", "the main window", 60_000);
  await evaluate("[...document.querySelectorAll('.nav-item')].find((n) => n.querySelector('strong')?.textContent === '配置')?.click(), true");
  await uiWait("document.querySelector('.configuration-modes') !== null", "the configuration page");
  await evaluate("[...document.querySelectorAll('.configuration-modes button')].find((b) => b.textContent.includes('生成新配置')).click(), true");
  await uiWait("document.querySelector('.config-product-list button') !== null", "the generator");

  // --- 1200 × 800: three columns, each scrolling inside, the page still.
  await pageArea(1200, 800);
  await product("Nginx");
  const layout = await threeColumns();
  const rowHeights = await evaluate("[...document.querySelectorAll('.config-feature-list > label')].map((row) => row.getBoundingClientRect().height)");
  const pageStill = await scrollState(".content");
  check("goal_catalog_reference_viewport_keeps_three_columns_visible_and_non_overlapping",
    layout.ok && layout.products.width >= 230 && layout.products.height > 500 && layout.editor.height > 500 && layout.preview.height > 500 &&
      pageStill.max === 0 && rowHeights.length > 10 && Math.max(...rowHeights) <= 120,
    { products: layout.products, editor: layout.editor, preview: layout.preview, pageOverflow: pageStill.max, tallestRow: Math.max(...rowHeights) });
  await shot("nginx-1200x800");

  await product("Apache HTTP Server");
  await select("apache", "client-body-limit");
  let below = await editorBelowRow("apache", "client-body-limit");
  check("apache_catalog_renders_inline_editor_and_preview_in_the_three_column_workspace", below.ok && (await threeColumns()).ok, below);
  await shot("apache-inline-editor");

  await product("MySQL");
  await select("mysql", "max-connections");
  below = await editorBelowRow("mysql", "max-connections");
  check("mysql_catalog_renders_inline_editor_and_preview_in_the_three_column_workspace", below.ok && (await threeColumns()).ok, below);

  // PostgreSQL and MariaDB: every reviewed version is a choice of its own, a
  // search narrows the rows, and the found row opens its editor below it.
  const search = (text) => evaluate(`(() => { const el = document.querySelector('.config-search input'); Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(el, ${JSON.stringify(text)}); el.dispatchEvent(new Event('input', { bubbles: true })); return true; })()`);
  // The search box also looks the sentence up as a goal, a quarter second
  // after typing; measure once those results are in, as an operator sees them.
  const goalsSettled = () => uiWait("!(document.querySelector('[data-testid=\"config-goal-results\"]')?.textContent.includes('正在按目标查找') ?? false)", "the goal search to settle");
  await product("PostgreSQL");
  const postgresqlVersions = await evaluate("[...document.querySelectorAll('input[data-testid^=\"config-version-postgresql-\"]')].map((input) => input.dataset.testid.slice('config-version-postgresql-'.length))");
  await search("锁等待 deadlock_timeout");
  await sleep(300);
  await goalsSettled();
  const postgresqlRows = await evaluate("[...document.querySelectorAll('[data-testid^=\"config-feature-row-postgresql-\"]')].map((row) => row.dataset.testid.slice('config-feature-row-postgresql-'.length))");
  await select("postgresql", "lock-wait-logging");
  const postgresqlBelow = await editorBelowRow("postgresql", "lock-wait-logging");
  await search("");
  await product("MariaDB");
  const mariadbVersions = await evaluate("[...document.querySelectorAll('input[data-testid^=\"config-version-mariadb-\"]')].map((input) => input.dataset.testid.slice('config-version-mariadb-'.length))");
  await search("日志保留");
  await sleep(300);
  await goalsSettled();
  const mariadbRows = await evaluate("[...document.querySelectorAll('[data-testid^=\"config-feature-row-mariadb-\"]')].map((row) => row.dataset.testid.slice('config-feature-row-mariadb-'.length))");
  await select("mariadb", "binary-log-retention");
  const mariadbBelow = await editorBelowRow("mariadb", "binary-log-retention");
  await search("");
  check("postgresql_and_mariadb_catalogs_render_versions_search_and_inline_editors",
    ["14", "15", "16", "17", "18"].every((version) => postgresqlVersions.some((id) => id.includes(version))) &&
      ["10-11", "11-4", "11-8", "12-3"].every((version) => mariadbVersions.some((id) => id.includes(version))) &&
      postgresqlRows.includes("lock-wait-logging") && !postgresqlRows.includes("connection-capacity") && postgresqlBelow.ok &&
      mariadbRows.includes("binary-log-retention") && mariadbBelow.ok,
    { postgresqlVersions, mariadbVersions, postgresqlRows, mariadbRows, postgresqlBelow: postgresqlBelow.ok, mariadbBelow: mariadbBelow.ok });

  await product("Redis");
  await select("redis", "slow-log");
  below = await editorBelowRow("redis", "slow-log");
  check("redis_catalog_renders_editor_directly_below_the_selected_row", below.ok && (await threeColumns()).ok, below);

  await product("Apache Tomcat");
  await select("tomcat", "connector-limits");
  below = await editorBelowRow("tomcat", "connector-limits");
  check("tomcat_catalog_renders_editor_directly_below_the_selected_row", below.ok && (await threeColumns()).ok, below);
  await shot("tomcat-inline-editor");

  // --- Long output scrolls inside the preview; the page and editor stay put.
  await product("Nginx");
  // The legacy test's own long set, less the two that need typed values
  // (paths for 403, networks for the source allow-list), plus other
  // independent reverse-proxy features so the output passes 50 lines.
  await enableOnly("nginx", [
    "security-headers", "disable-directory-listing", "restrict-request-methods", "hide-version",
    "gzip-compression", "static-asset-caching", "websocket-proxy", "health-check", "deny-hidden-files",
    "deny-sensitive-files", "keepalive-tuning", "proxy-timeouts", "request-id-headers", "client-io-timeouts",
  ]);
  await generate();
  const nginxLines = await evaluate("document.querySelector('[data-testid=\"config-artifact-preview-text\"]').textContent.split('\\n').length");
  // The generated text reaches the window as text only, inside its bound, and
  // is the whole artifact when the panel does not say it was cut.
  const asText = await evaluate(`(() => {
    const pre = document.querySelector('[data-testid="config-artifact-preview-text"]');
    const meta = pre.previousElementSibling;
    const stated = Number((meta.textContent.match(/(\\d+) 字节/) ?? [])[1]);
    const bytes = new TextEncoder().encode(pre.textContent).length;
    return {
      onlyText: pre.childElementCount === 0 && [...pre.childNodes].every((node) => node.nodeType === Node.TEXT_NODE),
      bytes, stated, truncated: meta.dataset.configPreviewTruncated,
    };
  })()`);
  check("preview_is_bounded_and_never_interprets_text",
    asText.onlyText && asText.bytes <= 32 * 1024 && asText.truncated === "false" && asText.bytes === asText.stated, asText);
  let scrolled = await previewScrollsAlone();
  check("nginx_quick_preview_scrolls_independently_through_long_output", nginxLines > 50 && scrolled.ok, { nginxLines, ...scrolled });
  await shot("nginx-preview-bottom");

  await pageArea(1200, 600);
  await product("Redis");
  await enableAll("redis");
  await generate();
  const redisLines = await evaluate("document.querySelector('[data-testid=\"config-artifact-preview-text\"]').textContent.split('\\n').length");
  scrolled = await previewScrollsAlone();
  check("redis_quick_preview_scrolls_to_the_last_generated_directive", redisLines > 30 && scrolled.ok, { redisLines, ...scrolled });

  await product("MariaDB");
  await enableAll("mariadb");
  const mariadbEnabled = await evaluate("[...document.querySelectorAll('input[data-testid^=\"config-feature-mariadb-\"]')].filter((box) => box.checked).length");
  await generate();
  scrolled = await previewScrollsAlone();
  check("mariadb_quick_preview_scrolls_independently_through_all_fifteen_features", mariadbEnabled === 15 && scrolled.ok, { mariadbEnabled, ...scrolled });
  await shot("mariadb-preview-bottom");

  // Tomcat is three files: the last one, read to its end inside the preview.
  await product("Apache Tomcat");
  await enableAll("tomcat", ["deny-all-requests"]);
  await generate();
  const tabs = await evaluate("[...document.querySelectorAll('.config-artifact-tabs button')].map((tab) => tab.textContent)");
  await evaluate("[...document.querySelectorAll('.config-artifact-tabs button')].at(-1).click(), true");
  await sleep(300);
  const lastFile = await evaluate("document.querySelector('[data-testid=\"config-artifact-preview-text\"]').textContent");
  scrolled = await previewScrollsAlone();
  check("tomcat_three_artifact_preview_scrolls_independently_to_the_last_file",
    tabs.length === 3 && tabs.at(-1).endsWith("web.xml") && lastFile.trimEnd().endsWith("</web-app>") && scrolled.ok,
    { tabs, lastFileEnd: lastFile.trimEnd().slice(-40), ...scrolled });
  await shot("tomcat-web-xml-bottom");

  // --- Not a legacy test: a window too narrow for three columns stacks the
  // preview under the editor, and the page scrolls down to it again.
  await app.setViewport(1100, 760);
  await sleep(500);
  const narrow = await evaluate(`(() => {
    const editor = document.querySelector('.config-editor').getBoundingClientRect();
    const preview = document.querySelector('.config-preview').getBoundingClientRect();
    const content = document.querySelector('.content');
    return { stacked: preview.top >= editor.bottom - 1, pageScrolls: content.scrollHeight > content.clientHeight,
      editorScrollsAlone: document.querySelector('.config-editor').scrollHeight > document.querySelector('.config-editor').clientHeight + 1 };
  })()`);
  check("narrow_window_stacks_preview_under_editor_and_scrolls_the_page", narrow.stacked && narrow.pageScrolls && !narrow.editorScrollsAlone, narrow);
  await shot("narrow-1100");

  // --- The visual workspace: long rows stay one line, the tree scrolls inside
  // its bounded panel, and a short window scrolls the page to the full text.
  await evaluate("[...document.querySelectorAll('.configuration-modes button')].find((b) => b.textContent.includes('可视化编辑')).click(), true");
  await uiWait("document.querySelector('[data-testid=\"config-visual-empty\"]') !== null", "the visual editor");
  await pageArea(1200, 600);
  await evaluate("[...document.querySelectorAll('.config-visual-empty-actions button')].find((b) => b.textContent.includes('新建比赛模板')).click(), true");
  await uiWait("document.querySelectorAll('.config-visual-row').length > 5", "the template rows");
  // A long value, added through the editor's own form, to see it bounded.
  const longValue = `/var/www/${"可读摘要".repeat(40)}`;
  await evaluate(`(() => {
    const kind = [...document.querySelectorAll('[data-testid="config-visual-add"] .config-visual-choice label')].find((l) => l.textContent.trim() === '指令');
    kind?.querySelector('input')?.click();
    return true;
  })()`);
  await sleep(200);
  const added = await evaluate(`(() => {
    const panel = document.querySelector('[data-testid="config-visual-add"]');
    const inputs = [...panel.querySelectorAll('input:not([type=checkbox]):not([type=radio])')].filter((input) => input.dataset.testid !== 'config-visual-note-text');
    if (inputs.length < 2) return false;
    const set = (el, value) => { Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(el, value); el.dispatchEvent(new Event('input', { bubbles: true })); };
    set(inputs[0], 'root'); set(inputs[1], ${JSON.stringify(longValue)});
    const button = [...panel.querySelectorAll('button')].find((b) => b.textContent.trim().startsWith('添加') && !b.disabled);
    if (!button) return false;
    button.click();
    return true;
  })()`);
  await sleep(800);
  const visual = await evaluate(`(() => {
    const rows = [...document.querySelectorAll('.config-visual-row')];
    const long = rows.find((row) => (row.querySelector('.config-visual-row-preview')?.textContent ?? '').includes('可读摘要'));
    const tree = document.querySelector('.config-visual-rows');
    const label = long?.querySelector('.config-visual-row-preview');
    return {
      rows: rows.length,
      tallest: Math.max(...rows.map((row) => row.getBoundingClientRect().height)),
      // Tall enough for what it shows: the name and the value lines both sit
      // inside the row, none clipped by it (the GPUI layout's 56px minimum).
      linesFit: rows.every((row) => {
        const box = row.getBoundingClientRect();
        return [...row.querySelectorAll('.config-visual-row-label, .config-visual-row-preview')]
          .filter((line) => line.textContent !== '')
          .every((line) => { const r = line.getBoundingClientRect(); return r.height > 0 && r.top >= box.top - 0.5 && r.bottom <= box.bottom + 0.5; });
      }),
      misfit: rows.map((row) => {
        const box = row.getBoundingClientRect();
        const bad = [...row.querySelectorAll('.config-visual-row-label, .config-visual-row-preview')]
          .filter((line) => line.textContent !== '')
          .map((line) => { const r = line.getBoundingClientRect(); return { cls: line.className, h: r.height, top: r.top - box.top, bottom: box.bottom - r.bottom }; })
          .filter((r) => !(r.h > 0 && r.top >= -0.5 && r.bottom >= -0.5));
        return bad.length === 0 ? null : { row: row.textContent.slice(0, 40), rowHeight: box.height, bad };
      }).filter((entry) => entry !== null).slice(0, 3),
      longFound: long !== undefined,
      longTruncated: label !== undefined && label !== null && label.scrollWidth > label.clientWidth && getComputedStyle(label).textOverflow === 'ellipsis',
      longOneLine: label ? label.getBoundingClientRect().height < 24 : false,
      treeScrolls: tree.scrollHeight > tree.clientHeight && /(auto|scroll)/.test(getComputedStyle(tree).overflowY),
      // The tree panel sticks to the top of the page area as the page
      // scrolls; bounded means it then fits inside it.
      treePanel: document.querySelector('.config-visual-tree').getBoundingClientRect().height,
      area: document.querySelector('.content').getBoundingClientRect().height,
    };
  })()`);
  check("visual_workspace_layout_keeps_small_windows_scrollable_and_panels_bounded",
    added && visual.longFound && visual.longTruncated && visual.longOneLine && visual.tallest <= 90 && visual.linesFit && visual.treeScrolls &&
      visual.treePanel <= visual.area,
    { added, ...visual });
  await shot("visual-1200x600");

  await pageArea(1200, 420);
  await evaluate("document.querySelector('.content').scrollTop = 0, true");
  await sleep(200);
  const area = await rect(".content");
  const initial = { page: await scrollState(".content"), preview: await rect('[data-testid="config-visual-preview"]') };
  const header = await rect(".configuration-modes");
  await wheel(header.left + 20, header.top + header.height / 2, 5_000);
  const bottom = { page: await scrollState(".content"), preview: await rect('[data-testid="config-visual-preview"]') };
  check("short_viewport_scrolls_page_from_header_to_full_preview",
    // Before: the page overflows and the full text starts below what is shown.
    initial.page.max > 0 && initial.preview.top >= area.bottom - EDGE &&
      // After one wheel gesture over the header: the page is at its bottom and
      // the full text is on screen, its bottom edge included.
      Math.abs(bottom.page.top - bottom.page.max) <= 1 &&
      bottom.preview.top < area.bottom && bottom.preview.bottom > area.top && bottom.preview.bottom <= area.bottom + EDGE,
    { area, initial, bottom });
  await shot("visual-1200x420-bottom");

  check("the probe saw no console errors", consoleErrors.length === 0, consoleErrors.slice(0, 3));
} catch (error) {
  failures += 1;
  console.error(`FAILED: ${error instanceof Error ? error.message : String(error)}`);
} finally {
  await app?.close();
  fs.writeFileSync(path.join(evidence, "report.json"), `${JSON.stringify({
    schema: "lovelyhawk-config-layout-probe/v1",
    status: failures === 0 ? "PASS" : "FAIL",
    generatedAt: new Date().toISOString(),
    checks,
  }, null, 2)}\n`);
  if (path.dirname(dataRoot) === os.tmpdir()) fs.rmSync(dataRoot, { recursive: true, force: true, maxRetries: 10, retryDelay: 300 });
  console.log(`${failures === 0 ? "PASS" : "FAIL"}: ${checks.filter((entry) => entry.passed).length}/${checks.length}; evidence in ${evidence}`);
  process.exitCode = failures === 0 ? 0 : 1;
}
