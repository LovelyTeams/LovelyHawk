// Security reference under the Tauri shell: the offline catalog renders in
// full, search and language filters narrow it, an entry expands into plain
// text, copy goes through the host, and a favourite survives a restart. Runs
// the debug build twice against one throwaway data root; touches no target.
// Copied text lands in a file through the debug-only clipboard hook, so the
// system clipboard is left alone.

import { randomUUID } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { attach, launchDesktop, waitFor } from "./cdp.mjs";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const executable = path.join(repositoryRoot, "target", "debug", process.platform === "win32" ? "lovelyhawk.exe" : "lovelyhawk");
const runRoot = path.join(repositoryRoot, "target", "desktop-debug", `security-reference-${randomUUID()}`);
const evidence = path.join(runRoot, "evidence");
const clipboardFile = path.join(runRoot, "clipboard.txt");
const catalog = JSON.parse(fs.readFileSync(path.join(repositoryRoot, "ui", "assets", "security_reference.json"), "utf8"));
const catalogSize = catalog.snippets.length;
const checks = [];
function check(name, ok, detail = null) {
  checks.push({ name, ok: Boolean(ok), detail });
  console.log(`${ok ? "PASS" : "FAIL"} ${name}${detail === null ? "" : ` — ${JSON.stringify(detail)}`}`);
}

fs.mkdirSync(evidence, { recursive: true });

async function run(phase, scenario) {
  const port = 9950 + Math.floor(Math.random() * 40);
  const { child, output } = launchDesktop({
    executable,
    archiveRoot: runRoot,
    port,
    extraEnv: { LOVELYHAWK_TEST_CLIPBOARD_FILE: clipboardFile },
  });
  let exitCode = null;
  child.once("exit", (code) => { exitCode = code; });
  const errors = [];
  try {
    const { session } = await attach(port, (url) => /^https?:\/\/tauri\.localhost\/(index\.html)?$/u.test(url));
    session.onEvent((method, params) => {
      if (method === "Runtime.exceptionThrown" || (method === "Runtime.consoleAPICalled" && params?.type === "error")) {
        errors.push(JSON.stringify(params).slice(0, 1_500));
      }
    });
    await session.send("Runtime.enable");
    await waitFor(() => session.evaluate(`[...document.querySelectorAll('.nav-item')].some((item) => item.textContent.includes('安全速查'))`), { label: "the navigation" });
    await session.evaluate(`[...document.querySelectorAll('.nav-item')].find((item) => item.textContent.includes('安全速查')).click(), true`);
    await waitFor(() => session.evaluate("document.querySelectorAll('.snippet-card').length > 0"), { timeoutMs: 20_000, label: "the catalog" });
    await scenario(session);
    check(`${phase}: no console errors`, errors.length === 0, errors.slice(0, 3));
    await session.evaluate("document.querySelector('[data-testid=\"window-close\"]').click(), true");
    await waitFor(() => exitCode !== null, { timeoutMs: 15_000, label: "exit" }).catch(() => undefined);
    check(`${phase}: the app exits cleanly`, exitCode === 0, exitCode);
  } catch (error) {
    check(`${phase}: completed`, false, error instanceof Error ? error.message : String(error));
    console.error(output.join("").slice(-3_000));
  } finally {
    if (exitCode === null) child.kill();
  }
}

const count = "Number(document.querySelector('.security-reference .result-count strong')?.textContent ?? -1)";
const cards = "document.querySelectorAll('.snippet-card').length";
function setSearch(value) {
  return `(() => {
    const input = document.querySelector('input[aria-label="搜索安全速查目录"]');
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(input, ${JSON.stringify(value)});
    input.dispatchEvent(new Event('input', { bubbles: true }));
    return true;
  })()`;
}

let favouriteTitle = null;
await run("first launch", async (session) => {
  const full = await session.evaluate(`({ count: ${count}, cards: ${cards} })`);
  check("the whole offline catalog is listed", full.count === catalogSize && full.cards === catalogSize, { ...full, catalogSize });

  const remote = await session.evaluate(`performance.getEntriesByType('resource').map((entry) => entry.name).filter((name) => !/^(https?:\\/\\/(tauri|ipc)\\.localhost\\/|ipc:|data:)/u.test(name))`);
  check("nothing loads from outside the application", remote.length === 0, remote.slice(0, 5));

  await session.evaluate(setSearch("redis"));
  const searched = await waitFor(() => session.evaluate(`(() => { const shown = ${count}; return shown < ${catalogSize} ? shown : null; })()`), { timeoutMs: 5_000, label: "the search" }).catch(() => -1);
  check("search narrows the list", searched > 0 && searched < catalogSize, searched);
  await session.evaluate(setSearch("zz-no-such-entry-zz"));
  const empty = await waitFor(() => session.evaluate(`${count} === 0 && document.querySelector('.security-reference .empty-state') !== null`), { timeoutMs: 5_000, label: "the empty state" }).catch(() => false);
  check("a search with no match says so", empty);
  await session.evaluate(setSearch(""));

  const language = await session.evaluate(`(() => {
    const pills = [...document.querySelectorAll('.language-strip .language-pill')];
    const second = pills[1];
    second.click();
    return { pills: pills.length, label: second.textContent, group: document.querySelector('.language-strip').getAttribute('role') };
  })()`);
  const filtered = await waitFor(() => session.evaluate(`(() => {
    const pressed = [...document.querySelectorAll('.language-strip .language-pill')].filter((pill) => pill.getAttribute('aria-pressed') === 'true').map((pill) => pill.textContent);
    const shown = ${count};
    return shown < ${catalogSize} && pressed.length === 1 ? { shown, pressed } : null;
  })()`), { timeoutMs: 5_000, label: "the language filter" }).catch(() => null);
  check("a language filter narrows the list and shows which one is on", filtered !== null && filtered.shown > 0 && filtered.pressed[0] === language.label && language.group === "group", { language, filtered });
  await session.evaluate("document.querySelector('.language-strip .language-pill').click(), true");

  const expanded = await session.evaluate(`(() => {
    const summary = document.querySelector('.snippet-card .snippet-summary');
    summary.click();
    return new Promise((resolve) => setTimeout(() => {
      const card = summary.closest('.snippet-card');
      const blocks = [...card.querySelectorAll('.snippet-detail pre')];
      resolve({
        ariaExpanded: summary.getAttribute('aria-expanded'),
        blocks: blocks.length,
        plainText: blocks.every((block) => block.children.length === 0),
        firstText: blocks[0]?.textContent ?? null,
        activeContent: card.querySelectorAll('script, iframe, img, a, object, embed').length,
      });
    }, 300));
  })()`);
  check("an entry expands into plain-text blocks", expanded.ariaExpanded === "true" && expanded.blocks > 0 && expanded.plainText && expanded.activeContent === 0, { ...expanded, firstText: undefined });

  fs.rmSync(clipboardFile, { force: true });
  await session.evaluate("document.querySelector('.snippet-card .snippet-detail .code-block button').click(), true");
  const copied = await waitFor(() => fs.existsSync(clipboardFile) ? fs.readFileSync(clipboardFile, "utf8") : null, { timeoutMs: 5_000, label: "the copied text" }).catch(() => null);
  const notice = await session.evaluate("document.querySelector('.security-reference .inline-notice')?.textContent ?? null");
  check("copy hands the exact block text to the host", copied === expanded.firstText && notice === "已复制到剪贴板。", { notice, length: copied?.length ?? null });

  favouriteTitle = await session.evaluate("document.querySelector('.snippet-card .snippet-summary strong').textContent");
  await session.evaluate("document.querySelector('.snippet-card .favorite-button').click(), true");
  const favourite = await waitFor(() => session.evaluate(`(() => {
    const label = document.querySelector('.snippet-card .favorite-button').getAttribute('aria-label');
    return label.startsWith('取消收藏') ? label : null;
  })()`), { timeoutMs: 8_000, label: "the favourite to save" }).catch(() => null);
  check("a favourite is saved and named after its entry", favourite === `取消收藏：${favouriteTitle}`, favourite);

  const unnamed = await session.evaluate(`[...document.querySelectorAll('.security-reference button, .security-reference input')].filter((element) => (element.getAttribute('aria-label') ?? element.textContent ?? '').trim() === '').length`);
  check("every control has an accessible name", unnamed === 0, unnamed);
  await session.screenshot(path.join(evidence, "security-reference.png"));
});

await run("after restart", async (session) => {
  const favourite = await session.evaluate(`[...document.querySelectorAll('.snippet-card')].filter((card) => card.querySelector('.favorite-button.active')).map((card) => card.querySelector('.snippet-summary strong').textContent)`);
  check("the favourite survives a restart", favourite.length === 1 && favourite[0] === favouriteTitle, favourite);
  await session.evaluate("[...document.querySelectorAll('.security-reference .chip')].find((chip) => chip.textContent.includes('仅收藏')).click(), true");
  const only = await waitFor(() => session.evaluate(`(() => {
    const chip = [...document.querySelectorAll('.security-reference .chip')].find((candidate) => candidate.textContent.includes('仅收藏'));
    return chip.getAttribute('aria-pressed') === 'true' ? ${count} : null;
  })()`), { timeoutMs: 5_000, label: "the favourites filter" }).catch(() => null);
  check("仅收藏 shows just the saved entry", only === 1, only);
});

const failed = checks.filter((entry) => !entry.ok);
fs.writeFileSync(path.join(evidence, "report.json"), `${JSON.stringify({
  schema: "lovelyhawk-security-reference-probe/v1",
  status: failed.length === 0 ? "PASS" : "FAIL",
  generatedAt: new Date().toISOString(),
  catalogSize,
  checks,
}, null, 2)}\n`);
console.log(`${failed.length === 0 ? "PASS" : "FAIL"}: ${checks.length - failed.length}/${checks.length}; evidence in ${evidence}`);
process.exitCode = failed.length === 0 ? 0 : 1;
