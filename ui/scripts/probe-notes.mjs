// Notes under the Tauri shell, end to end in the real window: empty states,
// create and edit (with hostile text that must stay text), tags and tag
// filtering, search, pinning, export through the host clipboard, the
// two-step delete with Escape and focus rules, saving on navigation, and
// persistence across a restart. Two launches against one throwaway data root;
// no target is involved. Copied text lands in a file through the debug-only
// clipboard hook, so the system clipboard is left alone.

import { randomUUID } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { attach, delay, launchDesktop, waitFor } from "./cdp.mjs";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const executable = path.join(repositoryRoot, "target", "debug", process.platform === "win32" ? "lovelyhawk.exe" : "lovelyhawk");
const runRoot = path.join(repositoryRoot, "target", "desktop-debug", `notes-${randomUUID()}`);
const evidence = path.join(runRoot, "evidence");
const clipboardFile = path.join(runRoot, "clipboard.txt");
const hostileTitle = `<img src=x onerror="document.title='owned'">调查 ${randomUUID().slice(0, 6)}`;
const hostileBody = "第一条线索\n<script>document.title='owned'</script>\n/tmp/.x 可疑";
const checks = [];
function check(name, ok, detail = null) {
  checks.push({ name, ok: Boolean(ok), detail });
  console.log(`${ok ? "PASS" : "FAIL"} ${name}${detail === null ? "" : ` — ${JSON.stringify(detail)}`}`);
}

fs.mkdirSync(evidence, { recursive: true });

async function run(phase, scenario) {
  const port = 10_000 + Math.floor(Math.random() * 200);
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
    await openPage(session, "笔记");
    await waitFor(() => session.evaluate("document.querySelector('.notes-list')?.getAttribute('aria-busy') === 'false'"), { timeoutMs: 20_000, label: "the notes list" });
    await scenario(session);
    check(`${phase}: no console errors`, errors.length === 0, errors.slice(0, 3));
    check(`${phase}: hostile text never ran`, await session.evaluate("document.title !== 'owned'"));
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

async function openPage(session, title) {
  await waitFor(() => session.evaluate(`[...document.querySelectorAll('.nav-item')].some((item) => item.textContent.includes(${JSON.stringify(title)}))`), { label: "the navigation" });
  await session.evaluate(`[...document.querySelectorAll('.nav-item')].find((item) => item.textContent.includes(${JSON.stringify(title)})).click(), true`);
}

const setValue = (selector, value) => `(() => {
  const element = document.querySelector(${JSON.stringify(selector)});
  const prototype = element instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
  Object.getOwnPropertyDescriptor(prototype, 'value').set.call(element, ${JSON.stringify(value)});
  element.dispatchEvent(new Event('input', { bubbles: true }));
  return true;
})()`;
const clickText = (selector, text) => `(() => {
  const element = [...document.querySelectorAll(${JSON.stringify(selector)})].find((candidate) => candidate.textContent.trim() === ${JSON.stringify(text)});
  if (!element || element.disabled) return false;
  element.click();
  return true;
})()`;
const state = `({
  total: Number((document.querySelector('.notes-list-meta strong')?.textContent ?? '').replace(/\\D+/gu, '') || -1),
  rows: [...document.querySelectorAll('.notes-list .note-row')].map((row) => ({
    title: row.querySelector('strong')?.textContent ?? null,
    pinned: row.querySelector('i')?.getAttribute('aria-label') ?? null,
  })),
  empty: document.querySelector('.notes-empty')?.textContent ?? null,
  editorEmpty: document.querySelector('.notes-editor-empty h2')?.textContent ?? null,
  status: document.querySelector('.notes-editor-status > span')?.textContent ?? null,
  notice: document.querySelector('.notes-notice:not(.error)')?.textContent ?? null,
  error: document.querySelector('.notes-notice.error')?.textContent ?? null,
  title: document.querySelector('input[aria-label="笔记标题"]')?.value ?? null,
  body: document.querySelector('textarea[aria-label="笔记正文"]')?.value ?? null,
  tags: [...document.querySelectorAll('.note-tag-filter')].map((tag) => tag.textContent),
  query: document.querySelector('input[aria-label="搜索笔记"]')?.value ?? null,
  busy: document.querySelector('.notes-editor-panel')?.getAttribute('aria-busy') === 'true',
})`;
const until = (session, predicate, label, timeoutMs = 10_000) =>
  waitFor(async () => { const value = await session.evaluate(state); return predicate(value) ? value : null; }, { timeoutMs, label }).catch(async () => session.evaluate(state));

await run("first launch", async (session) => {
  let now = await session.evaluate(state);
  check("an empty library says so in the list and the editor", now.total === 0 && now.empty === "还没有笔记。点右上角“新建笔记”开始记录。" && now.editorEmpty === "开始记录调查线索", now);
  check("title and body inputs are bounded", await session.evaluate("(() => { document.querySelector('.notes-heading-actions button:last-child').click(); return true; })()") &&
    await waitFor(() => session.evaluate("document.querySelector('input[aria-label=\"笔记标题\"]')?.maxLength === 256 && document.querySelector('textarea[aria-label=\"笔记正文\"]')?.maxLength === 1048576"), { timeoutMs: 10_000, label: "the bounded editor" }).catch(() => false));
  now = await until(session, (value) => value.total === 1 && value.notice === "已新建笔记。", "the first note");
  check("新建笔记 creates and opens a note", now.total === 1 && now.notice === "已新建笔记。" && now.title !== null, now);

  await session.evaluate(setValue('input[aria-label="笔记标题"]', hostileTitle));
  await session.evaluate(setValue('textarea[aria-label="笔记正文"]', hostileBody));
  now = await session.evaluate(state);
  check("an edit is marked unsaved", now.status === "有未保存更改", now.status);
  await session.evaluate(clickText(".notes-editor-toolbar button", "保存"));
  now = await until(session, (value) => value.status === "所有更改已保存" && value.rows[0]?.title === hostileTitle, "the save");
  check("saving keeps markup as literal text", now.status === "所有更改已保存" && now.rows[0]?.title === hostileTitle &&
    await session.evaluate("document.querySelectorAll('.notes-page img, .notes-page script').length === 0"), now.rows);

  await session.evaluate(setValue('input[aria-label="新标签"]', "ioc"));
  await session.evaluate("document.querySelector('.notes-tags form button[type=\"submit\"]').click(), true");
  now = await until(session, (value) => value.tags.includes("#ioc"), "the tag");
  check("a tag is added", now.tags.includes("#ioc"), now.tags);

  // Fill the note to its 32-tag limit, then one more: the refusal is an error
  // state in plain words, and nothing already saved is lost.
  for (let index = 2; index <= 33; index += 1) {
    await session.evaluate(setValue('input[aria-label="新标签"]', `t${index}`));
    await session.evaluate("document.querySelector('.notes-tags form button[type=\"submit\"]').click(), true");
    if (index <= 32) await until(session, (value) => value.tags.includes(`#t${index}`), `tag ${index}`);
  }
  now = await until(session, (value) => value.error !== null, "the refused 33rd tag");
  check("a 33rd tag is refused in plain Chinese and the 32 stay", now.error?.startsWith("笔记操作没有完成") === true && now.tags.length === 32 && !now.tags.includes("#t33"), { error: now.error, tags: now.tags.length });
  await session.screenshot(path.join(evidence, "notes-tag-limit.png"));
  // Take them off again so the rest of the run reads as before.
  for (let index = 2; index <= 32; index += 1) {
    await session.evaluate(`document.querySelector('button[aria-label="移除标签 t${index}"]')?.click(), true`);
    await until(session, (value) => !value.tags.includes(`#t${index}`), `removing tag ${index}`);
  }
  now = await session.evaluate(state);
  check("removing tags works and leaves the first one", now.tags.length === 1 && now.tags[0] === "#ioc", now.tags);

  // A second note, so filters and pinning have something to separate.
  await session.evaluate(clickText(".notes-heading-actions button", "新建笔记"));
  now = await until(session, (value) => value.total === 2, "the second note");
  await session.evaluate(setValue('input[aria-label="笔记标题"]', "第二条"));
  await session.evaluate(clickText(".notes-editor-toolbar button", "保存"));
  now = await until(session, (value) => value.total === 2 && value.status === "所有更改已保存" && value.rows.some((row) => row.title === "第二条"), "the second save");
  check("a second note is listed", now.total === 2, now.rows);

  await session.evaluate(setValue('input[aria-label="搜索笔记"]', "#ioc"));
  now = await until(session, (value) => value.total === 1, "the tag filter");
  check("filtering by #tag finds only the tagged note", now.total === 1 && now.rows[0]?.title === hostileTitle, now.rows);
  await session.evaluate(setValue('input[aria-label="搜索笔记"]', "zz-nothing-zz"));
  now = await until(session, (value) => value.total === 0, "the empty search");
  check("a search with no match says so", now.total === 0 && now.empty === "没有匹配的笔记，换个关键词或 #标签 试试。", now);
  await session.evaluate(setValue('input[aria-label="搜索笔记"]', ""));
  now = await until(session, (value) => value.total === 2, "the full list");

  // Pin the older note; it moves to the top.
  await session.evaluate(`[...document.querySelectorAll('.notes-list .note-row')].find((row) => row.querySelector('strong')?.textContent === ${JSON.stringify(hostileTitle)}).click(), true`);
  await until(session, (value) => value.title === hostileTitle, "the first note to open");
  await session.evaluate(clickText(".notes-editor-toolbar button", "置顶"));
  now = await until(session, (value) => value.notice === "笔记已置顶。" && value.rows[0]?.title === hostileTitle && value.rows[0]?.pinned === "已置顶", "the pin");
  check("pinning puts the note first and says it is pinned", now.rows[0]?.title === hostileTitle && now.rows[0]?.pinned === "已置顶" && now.rows[1]?.pinned === "未置顶", now.rows);

  fs.rmSync(clipboardFile, { force: true });
  await session.evaluate(clickText(".notes-editor-toolbar button", "导出"));
  now = await until(session, (value) => value.notice === "已复制 1 条笔记的纯文本导出。", "the export");
  const exported = fs.existsSync(clipboardFile) ? fs.readFileSync(clipboardFile, "utf8") : "";
  check("exporting one note copies its plain text through the host", now.notice === "已复制 1 条笔记的纯文本导出。" && exported.includes(hostileTitle) && exported.includes("第一条线索"), { notice: now.notice, length: exported.length });
  fs.rmSync(clipboardFile, { force: true });
  await session.evaluate(clickText(".notes-heading-actions button", "导出全部"));
  now = await until(session, (value) => value.notice === "已复制 2 条笔记的纯文本导出。", "the full export");
  const all = fs.existsSync(clipboardFile) ? fs.readFileSync(clipboardFile, "utf8") : "";
  check("导出全部 copies every note", now.notice === "已复制 2 条笔记的纯文本导出。" && all.includes("第二条") && all.includes(hostileTitle), now.notice);

  // Leaving the page with an unsaved edit saves it.
  await session.evaluate(setValue('textarea[aria-label="笔记正文"]', `${hostileBody}\n离开前补充`));
  await openPage(session, "安全速查");
  await waitFor(() => session.evaluate("document.querySelector('.notes-page') === null"), { timeoutMs: 10_000, label: "leaving notes" }).catch(() => undefined);
  await openPage(session, "笔记");
  await waitFor(() => session.evaluate("document.querySelector('.notes-list')?.getAttribute('aria-busy') === 'false'"), { timeoutMs: 20_000, label: "the notes list again" });
  await session.evaluate(`[...document.querySelectorAll('.notes-list .note-row')].find((row) => row.querySelector('strong')?.textContent === ${JSON.stringify(hostileTitle)}).click(), true`);
  now = await until(session, (value) => value.body?.endsWith("离开前补充") === true, "the saved-on-leave body");
  check("an edit is saved when the page is left", now.body?.endsWith("离开前补充") === true, now.body?.slice(-20));

  // Delete the second note: plan, Escape cancels, then confirm.
  await session.evaluate(`[...document.querySelectorAll('.notes-list .note-row')].find((row) => row.querySelector('strong')?.textContent === '第二条').click(), true`);
  await until(session, (value) => value.title === "第二条", "the second note to open");
  await session.evaluate(clickText(".notes-editor-toolbar button", "删除"));
  const dialog = await waitFor(() => session.evaluate(`(() => {
    const dialog = document.querySelector('[role="dialog"][aria-labelledby="note-delete-title"]');
    return dialog ? { title: dialog.querySelector('h2').textContent, focus: document.activeElement?.textContent ?? null, eyebrow: dialog.querySelector('.eyebrow')?.textContent ?? null, backgroundInert: document.querySelector('.app-frame')?.hasAttribute('inert') ?? false } : null;
  })()`), { timeoutMs: 10_000, label: "the delete dialog" }).catch(() => null);
  check("delete asks first, with focus on 取消 and the page behind inert", dialog?.title === "永久删除这条笔记？" && dialog?.focus === "取消" && dialog?.eyebrow === "危险操作" && dialog?.backgroundInert === true, dialog);
  await session.screenshot(path.join(evidence, "notes-delete-dialog.png"));
  await session.send("Input.dispatchKeyEvent", { type: "keyDown", key: "Escape", code: "Escape", windowsVirtualKeyCode: 27 });
  await session.send("Input.dispatchKeyEvent", { type: "keyUp", key: "Escape", code: "Escape", windowsVirtualKeyCode: 27 });
  await delay(600);
  now = await session.evaluate(state);
  check("Escape cancels and the note stays", now.total === 2 && await session.evaluate("document.querySelector('[aria-labelledby=\"note-delete-title\"]') === null"), now.total);
  await session.evaluate(clickText(".notes-editor-toolbar button", "删除"));
  await waitFor(() => session.evaluate("document.querySelector('[aria-labelledby=\"note-delete-title\"]') !== null"), { timeoutMs: 10_000, label: "the delete dialog again" });
  await session.evaluate(clickText("[role=\"dialog\"] button", "确认永久删除"));
  now = await until(session, (value) => value.total === 1 && value.title === hostileTitle, "the delete");
  check("confirming deletes exactly that note and opens the one left", now.total === 1 && now.rows[0]?.title === hostileTitle && now.title === hostileTitle, now.rows);
  // The remaining note opens by itself; that must not wipe the result message.
  await delay(800);
  now = await session.evaluate(state);
  check("the verified-delete message stays on screen", now.notice === "笔记已永久删除，并完成审计与结果验证。", now.notice);
  await session.screenshot(path.join(evidence, "notes-after-delete.png"));
});

await run("after restart", async (session) => {
  const now = await until(session, (value) => value.total === 1, "the stored note", 15_000);
  check("the note, its pin and its tag survive a restart", now.total === 1 && now.rows[0]?.title === hostileTitle && now.rows[0]?.pinned === "已置顶", now.rows);
  await session.evaluate(`document.querySelector('.notes-list .note-row').click(), true`);
  const opened = await until(session, (value) => value.title === hostileTitle, "the stored note to open");
  check("its body and tag came back exactly", opened.body === `${hostileBody}\n离开前补充` && opened.tags.includes("#ioc"), { tags: opened.tags });
});

const failed = checks.filter((entry) => !entry.ok);
fs.writeFileSync(path.join(evidence, "report.json"), `${JSON.stringify({
  schema: "lovelyhawk-notes-probe/v1",
  status: failed.length === 0 ? "PASS" : "FAIL",
  generatedAt: new Date().toISOString(),
  checks,
}, null, 2)}\n`);
console.log(`${failed.length === 0 ? "PASS" : "FAIL"}: ${checks.length - failed.length}/${checks.length}; evidence in ${evidence}`);
process.exitCode = failed.length === 0 ? 0 : 1;
