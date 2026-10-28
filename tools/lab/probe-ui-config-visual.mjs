// 配置 → 可视化编辑 in the real Tauri window: an Nginx file as a tree.
//
// No lab host is needed — the editor works on local drafts. The system's open
// and save dialogs and the clipboard are scripted through the debug build's
// test hooks; everything after them (the document, every edit, the checks,
// the file written) is the real path. Files are read back here, not by the
// program that wrote them.
//
//   node tools/lab/probe-ui-config-visual.mjs

import { randomUUID } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { startDesktop } from "./desktop.mjs";

const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const runId = randomUUID();
const evidence = path.join(repository, "target", "lab-config-visual", runId);
const files = path.join(evidence, "files");
fs.mkdirSync(files, { recursive: true });
const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "lovelyhawk-visual-"));
const checks = [];
let failures = 0;
let app = null;

function check(label, ok, detail = null) {
  checks.push({ label, passed: Boolean(ok), detail });
  if (!ok) failures += 1;
  console.log(`${ok ? "PASS" : "FAIL"} ${label}${ok || detail === null ? "" : ` — ${JSON.stringify(detail).slice(0, 500)}`}`);
}
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
async function until(predicate, label, timeoutMs = 30_000) {
  const end = Date.now() + timeoutMs;
  while (Date.now() < end) {
    try { if (await predicate()) return; } catch {}
    await sleep(200);
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
  const clickText = (selector, text) => evaluate(`(() => { const b = [...document.querySelectorAll(${JSON.stringify(selector)})].find((x) => x.textContent.trim().startsWith(${JSON.stringify(text)}) && !x.disabled); if (!b) throw new Error('missing ' + ${JSON.stringify(text)}); b.click(); return true; })()`);
  const setValue = (selector, value) => evaluate(`(() => { const el = document.querySelector(${JSON.stringify(selector)}); const proto = el instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype; Object.getOwnPropertyDescriptor(proto, 'value').set.call(el, ${JSON.stringify(value)}); el.dispatchEvent(new Event('input', { bubbles: true })); return true; })()`);
  const preview = () => evaluate("document.querySelector('[data-testid=\"config-visual-preview\"] pre')?.textContent ?? null");
  const labels = () => evaluate("[...document.querySelectorAll('.config-visual-row')].map((b) => b.querySelector('.config-visual-row-label').textContent)");
  const notice = () => evaluate("document.querySelector('.config-visual-notice')?.textContent ?? ''");
  const dirty = () => evaluate("document.querySelector('[data-testid=\"config-visual-dirty\"]') !== null");
  const selectRow = (label) => evaluate(`(() => { const b = [...document.querySelectorAll('.config-visual-row')].find((x) => x.querySelector('.config-visual-row-label').textContent === ${JSON.stringify(label)}); if (!b) throw new Error('no row ' + ${JSON.stringify(label)}); b.click(); return true; })()`);
  const dialog = () => evaluate("(() => { const d = document.querySelector('.dialog-host'); return d ? { title: d.querySelector('#dialog-host-title')?.textContent ?? '', focus: document.activeElement?.textContent ?? '' } : null; })()");
  const answerDialog = (text) => clickText(".dialog-host button", text);
  const pick = (selector, value) => evaluate(`(() => { const el = document.querySelector(${JSON.stringify(selector)}); if (!el) throw new Error('no ' + ${JSON.stringify(selector)}); Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, 'value').set.call(el, ${JSON.stringify(value)}); el.dispatchEvent(new Event('change', { bubbles: true })); return true; })()`);
  const textOf = (selector) => evaluate(`document.querySelector(${JSON.stringify(selector)})?.textContent ?? ''`);
  const valueOf = (selector) => evaluate(`document.querySelector(${JSON.stringify(selector)})?.value ?? null`);
  const addKind = (label) => evaluate(`[...document.querySelectorAll('[data-testid="config-visual-add"] .config-visual-choice label')].find((l) => l.textContent.trim() === ${JSON.stringify(label)}).querySelector('input').click(), true`);

  await uiWait("document.querySelector('.nav-item') !== null", "the main window", 60_000);
  await evaluate("[...document.querySelectorAll('.nav-item')].find((n) => n.textContent.includes('配置'))?.click(), true");
  await uiWait("document.querySelector('.configuration-modes') !== null", "the configuration page");
  await clickText(".configuration-modes button", "可视化编辑");
  await uiWait("document.querySelector('[data-testid=\"config-visual-empty\"]') !== null", "the visual editor");
  check("可视化编辑 is a mode of the configuration page and says what it is for before anything is open",
    await evaluate("document.querySelector('[data-testid=\"config-visual-empty\"]').textContent.includes('当成一棵树')"));

  // 1. The competition template as a tree.
  await clickText(".config-visual-empty-actions button", "新建比赛模板");
  await uiWait("document.querySelectorAll('.config-visual-row').length > 5", "the template rows");
  const templateText = await preview();
  const templateLabels = await labels();
  check("the template opens as a tree of blocks and directives, with its full text and nothing unsaved",
    templateLabels.some((label) => label.startsWith("块 · server")) && templateLabels.some((label) => label.startsWith("块 · http")) &&
    templateText.includes("server {") && !(await dirty()) &&
    (await evaluate("document.querySelector('[data-testid=\"config-visual-status\"]').textContent")).includes("比赛模板"),
    { labels: templateLabels.slice(0, 8) });
  const rowNotes = await evaluate("[...document.querySelectorAll('[data-testid=\"config-visual-row-help\"]')].map((n) => n.textContent)");
  check("the template explains itself in Chinese: comment lines in the file and a note under each known row",
    templateText.includes("# 工作进程用哪个系统账号运行；不要用 root。") && templateText.includes("# 默认站点：监听 80 端口") &&
    rowNotes.length >= 15 && rowNotes.some((note) => note.includes("站点监听的地址和端口")),
    { notes: rowNotes.length, sample: rowNotes.slice(0, 3) });

  // A Chinese word finds items by their note; it never reaches into values.
  await setValue(".config-visual-search input", "端口");
  await sleep(200);
  const byNote = await labels();
  check("searching 端口 in Chinese finds listen by its note, with the blocks around it",
    byNote.includes("指令 · listen") && !byNote.includes("指令 · user") &&
    byNote.every((label) => label === "指令 · listen" || label.startsWith("块 · ")), byNote);
  await setValue(".config-visual-search input", "");
  await sleep(200);

  // 2. Searching finds names and kinds, with the blocks around them, never values.
  await setValue(".config-visual-search input", "location");
  await sleep(200);
  const located = await labels();
  check("searching location shows the location blocks and the blocks they sit in, nothing else",
    located.length > 0 && located.some((label) => label.startsWith("块 · location")) &&
    located.every((label) => label.startsWith("块 · ")), located);
  await setValue(".config-visual-search input", "healthz");
  await sleep(200);
  check("a word that appears only in an argument finds nothing", (await labels()).length === 0 &&
    (await evaluate("document.querySelector('.config-visual-tree-empty')?.textContent ?? ''")).includes("不看参数"));
  await setValue(".config-visual-search input", "");
  await sleep(200);

  // A selection a search hides is dropped, so no edit lands on a row nobody sees.
  const serverLabel = templateLabels.find((label) => label.startsWith("块 · server"));
  await selectRow(serverLabel);
  await uiWait("document.querySelector('[data-testid=\"config-visual-selected\"]').textContent.includes('类型：块')", "the server selection");
  await setValue(".config-visual-search input", "upstream");
  await sleep(250);
  check("a search that hides the selected row drops the selection and its editor",
    !(await labels()).includes(serverLabel) &&
    (await evaluate("document.querySelector('[data-testid=\"config-visual-selected\"]').textContent.includes('在左边选择一行')")) &&
    (await evaluate("document.querySelector('[data-testid=\"config-visual-selected\"] form') === null")));
  await setValue(".config-visual-search input", "");
  await sleep(200);

  // 3. Add a directive inside the server block.
  await selectRow(serverLabel);
  await uiWait("document.querySelector('[data-testid=\"config-visual-selected\"]').textContent.includes('类型：块')", "the selected block");
  await evaluate("[...document.querySelectorAll('[data-testid=\"config-visual-add\"] .config-visual-choice label')].find((l) => l.textContent.trim() === '指令').querySelector('input').click(), true");
  await setValue("[data-testid=\"config-visual-add\"] .config-visual-field:nth-of-type(1) input", "server_name");
  await setValue("[data-testid=\"config-visual-add\"] .config-visual-field:nth-of-type(2) input", "probe.example.test");
  await clickText("[data-testid=\"config-visual-add\"] button", "添加指令");
  await until(async () => (await preview())?.includes("server_name probe.example.test;"), "the added directive");
  const added = await preview();
  check("a directive added inside the server block lands inside it, indented, and the document is marked unsaved",
    /server \{[\s\S]*\n {8}server_name probe\.example\.test;\n[\s\S]*\}/u.test(added) && await dirty() &&
    (await evaluate("document.querySelector('.config-visual-row.is-selected .config-visual-row-label')?.textContent")) === "指令 · server_name",
    added.slice(0, 600));
  check("by default a Chinese comment from the built-in note goes right above it, in the same edit",
    /\n {8}# 这个站点响应哪些域名。\n {8}server_name probe\.example\.test;\n/u.test(added) &&
    (await notice()).includes("上方附了一行中文注释"), added.slice(0, 900));
  const selectedHelp = await textOf("[data-testid=\"config-visual-help\"]");
  check("the selected directive says what it does, how it is usually written, and what to watch",
    selectedHelp.includes("作用") && selectedHelp.includes("这个站点响应哪些域名") &&
    selectedHelp.includes("常见写法") && selectedHelp.includes("server_name example.com") && selectedHelp.includes("注意"), selectedHelp);

  // 4. Edit it, then try to smuggle a second statement in.
  await setValue("[data-testid=\"config-visual-selected\"] .config-visual-field:nth-of-type(2) input", "probe2.example.test");
  await clickText("[data-testid=\"config-visual-selected\"] button", "保存修改");
  await until(async () => (await preview())?.includes("server_name probe2.example.test;"), "the edited directive");
  check("saving the selected row changes exactly that line",
    !(await preview()).includes("probe.example.test;") && (await notice()).includes("已更新指令 server_name"));
  const beforeInjection = await preview();
  await setValue("[data-testid=\"config-visual-selected\"] .config-visual-field:nth-of-type(2) input", "x; include /etc/passwd");
  await clickText("[data-testid=\"config-visual-selected\"] button", "保存修改");
  await uiWait("document.querySelector('.config-visual-notice.error') !== null", "the refusal");
  check("an argument carrying a second statement is refused and changes nothing",
    (await notice()).includes("没有通过语法检查") && (await preview()) === beforeInjection);

  // 5. Move it up one place.
  const indexOf = (text, needle) => text.indexOf(needle);
  await clickText("[data-testid=\"config-visual-selected\"] button", "上移");
  await until(async () => (await notice()).includes("已上移"), "the move");
  const movedText = await preview();
  check("上移 moves the line above its previous sibling and keeps it selected",
    indexOf(movedText, "server_name probe2.example.test;") < indexOf(beforeInjection, "server_name probe2.example.test;") &&
    (await evaluate("document.querySelector('.config-visual-row.is-selected .config-visual-row-label')?.textContent")) === "指令 · server_name");

  // 5b. The common items: picking one fills the name, a usual value and the note.
  // The http server is the first server in the file; its label counts children.
  const selectFirstServer = async () => {
    await evaluate("[...document.querySelectorAll('.config-visual-row')].find((b) => b.querySelector('.config-visual-row-label').textContent.startsWith('块 · server ·')).click(), true");
    await uiWait("document.querySelector('.config-visual-row.is-selected .config-visual-row-label')?.textContent.startsWith('块 · server ·') === true", "the http server");
  };
  await selectFirstServer();
  await addKind("指令");
  const offered = await evaluate("[...document.querySelectorAll('[data-testid=\"config-visual-suggest\"] option')].map((o) => o.value)");
  await pick("[data-testid=\"config-visual-suggest\"]", "server_tokens");
  await sleep(150);
  const picked = {
    name: await valueOf("[data-testid=\"config-visual-add\"] .config-visual-field:nth-of-type(1) input"),
    args: await valueOf("[data-testid=\"config-visual-add\"] .config-visual-field:nth-of-type(2) input"),
    note: await valueOf("[data-testid=\"config-visual-note-text\"]"),
    help: await textOf("[data-testid=\"config-visual-add-help\"]"),
  };
  check("inside a server block the list offers what fits there, and picking one fills its name, usual value and note",
    offered.includes("listen") && offered.includes("server_name") && !offered.includes("worker_connections") &&
    picked.name === "server_tokens" && picked.args === "off" && picked.note.includes("版本号") && picked.help.includes("注意"),
    { offered: offered.slice(0, 12), picked });
  await setValue("[data-testid=\"config-visual-note-text\"]", "不暴露版本号（探针）");
  await clickText("[data-testid=\"config-visual-add\"] button", "添加指令");
  await until(async () => (await preview())?.includes("# 不暴露版本号（探针）"), "the picked directive");
  check("a rewritten note is written as given, right above the item",
    /\n {8}# 不暴露版本号（探针）\n {8}server_tokens off;\n/u.test(await preview()));
  await selectFirstServer();
  await pick("[data-testid=\"config-visual-suggest\"]", "autoindex");
  await evaluate("document.querySelector('[data-testid=\"config-visual-note-toggle\"]').click(), true");
  await sleep(100);
  const withoutNote = await preview();
  await clickText("[data-testid=\"config-visual-add\"] button", "添加指令");
  await until(async () => (await preview()) !== withoutNote, "the directive without a note");
  const plain = await preview();
  check("turning the note off adds the item alone",
    /\n {8}autoindex off;\n/u.test(plain) && !/目录里没有首页文件/u.test(plain) &&
    plain.split("\n").length === withoutNote.split("\n").length + 1);
  await evaluate("document.querySelector('[data-testid=\"config-visual-note-toggle\"]').click(), true");

  // 6. Deleting a block with children asks first; 取消 keeps it.
  const locationWithChildren = (await labels()).find((label) => /^块 · location · \d+ 个子项$/u.test(label));
  await selectRow(locationWithChildren);
  await sleep(150);
  const beforeDelete = await preview();
  await clickText("[data-testid=\"config-visual-selected\"] button", "删除整个块");
  await until(async () => (await dialog()) !== null, "the delete question");
  const asked = await dialog();
  await answerDialog("取消");
  await until(async () => (await dialog()) === null, "the dialog to close");
  const countBefore = (await labels()).filter((label) => label === locationWithChildren).length;
  check("deleting a block with children asks first, and 取消 deletes nothing",
    asked.title.startsWith("删除 location") && (await preview()) === beforeDelete, asked);
  await clickText("[data-testid=\"config-visual-selected\"] button", "删除整个块");
  await until(async () => (await dialog()) !== null, "the delete question again");
  await answerDialog("删除整个块");
  await until(async () => (await notice()).includes("已删除块 location"), "the deletion");
  check("confirming removes the block with everything in it",
    (await labels()).filter((label) => label === locationWithChildren).length === countBefore - 1 &&
    (await preview()).length < beforeDelete.length);

  // 7. Save to a new file; the bytes are the text on screen. A second save
  //    to the same name never replaces it.
  const savedPath = path.join(files, "edited.conf");
  app.setDialogAnswers([savedPath]);
  await clickText(".config-visual-toolbar button", "另存为文件");
  await until(async () => (await notice()).includes("已另存为"), "the save");
  const onScreen = await preview();
  check("另存为 writes exactly the text on screen and clears the unsaved mark",
    fs.existsSync(savedPath) && fs.readFileSync(savedPath, "utf8") === onScreen && !(await dirty()));
  const savedBytes = fs.readFileSync(savedPath);
  app.setDialogAnswers([savedPath]);
  await clickText(".config-visual-toolbar button", "另存为文件");
  await uiWait("document.querySelector('.config-visual-notice.error') !== null", "the refused overwrite");
  check("saving over an existing file is refused and the file is untouched",
    Buffer.compare(fs.readFileSync(savedPath), savedBytes) === 0);

  // 8. Copy gives the same text.
  app.clearClipboard();
  await clickText(".config-visual-toolbar button", "复制全部");
  await until(async () => (await notice()).includes("已复制全部内容"), "the copy");
  check("复制全部 puts exactly the document's text on the clipboard", app.readClipboard() === onScreen);

  // 9. A file with CRLF line ends imports and saves back byte for byte.
  const crlf = "# probe\r\nevents {\r\n    worker_connections 64;\r\n}\r\nhttp {\r\n    server { listen 8081; }\r\n}";
  const crlfPath = path.join(files, "crlf.conf");
  fs.writeFileSync(crlfPath, crlf);
  app.setDialogAnswers([crlfPath]);
  await clickText(".config-visual-toolbar button", "导入本地文件");
  await until(async () => (await notice()).includes("已导入本地文件"), "the import");
  const crlfCopy = path.join(files, "crlf-copy.conf");
  app.setDialogAnswers([crlfCopy]);
  await clickText(".config-visual-toolbar button", "另存为文件");
  await until(async () => (await notice()).includes("已另存为"), "the CRLF save");
  check("an imported file with CRLF and no final newline saves back byte for byte",
    Buffer.compare(fs.readFileSync(crlfCopy), Buffer.from(crlf)) === 0 &&
    (await evaluate("document.querySelector('[data-testid=\"config-visual-status\"]').textContent")).includes("导入的文件"));

  // 10. A file holding a credential: hidden, locked, not copied, not shown.
  const secret = "probe-secret-6c1f";
  const secretPath = path.join(files, "auth.conf");
  fs.writeFileSync(secretPath, `server {\n    listen 80;\n    proxy_set_header Authorization "Bearer ${secret}";\n}\nserver {\n    listen 81;\n}\n`);
  app.setDialogAnswers([secretPath]);
  await clickText(".config-visual-toolbar button", "导入本地文件");
  await until(async () => (await notice()).includes("已导入本地文件") && (await labels()).length === 5, "the credential import");
  await selectRow("块 · server · 2 个子项");
  await sleep(150);
  check("a credential is never on the page: rows hidden, full text not shown, copy off, the block locked with a reason",
    !(await evaluate(`document.body.innerText.includes(${JSON.stringify(secret)})`)) &&
    (await evaluate("document.querySelector('.config-visual-banners').textContent.includes('疑似口令')")) &&
    (await evaluate("document.querySelector('[data-testid=\"config-visual-preview\"]').textContent.includes('不在这里显示全文')")) &&
    (await evaluate("[...document.querySelectorAll('.config-visual-toolbar button')].find((b) => b.textContent.trim() === '复制全部').disabled")) &&
    (await evaluate("document.querySelector('.config-visual-locked')?.textContent.includes('已隐藏') === true")));
  await selectRow("块 · server · 1 个子项");
  await sleep(150);
  check("the other server block stays editable",
    await evaluate("document.querySelector('[data-testid=\"config-visual-selected\"] button[type=submit]') !== null"));
  const secretCopy = path.join(files, "auth-copy.conf");
  app.setDialogAnswers([secretCopy]);
  await clickText(".config-visual-toolbar button", "另存为文件");
  await until(async () => (await notice()).includes("已另存为"), "the credential save");
  check("saving keeps the hidden value exactly as it was",
    Buffer.compare(fs.readFileSync(secretCopy), fs.readFileSync(secretPath)) === 0);
  await page.shot("config-visual-hidden.png");

  // 11. Unsaved edits are not dropped by switching mode.
  await clickText(".config-visual-toolbar button", "新建比赛模板");
  await uiWait("document.querySelectorAll('.config-visual-row').length > 5", "the template again");
  await evaluate("[...document.querySelectorAll('[data-testid=\"config-visual-add\"] .config-visual-choice label')].find((l) => l.textContent.trim() === '注释').querySelector('input').click(), true");
  await evaluate("[...document.querySelectorAll('[data-testid=\"config-visual-add\"] .config-visual-choice label')].find((l) => l.textContent.includes('最外层')).querySelector('input').click(), true");
  await setValue("[data-testid=\"config-visual-add\"] .config-visual-field input", "probe note");
  await clickText("[data-testid=\"config-visual-add\"] button", "添加注释");
  await until(async () => (await preview())?.includes("# probe note"), "the added comment");
  await clickText(".configuration-modes button", "生成新配置");
  await until(async () => (await dialog()) !== null, "the unsaved question");
  const unsaved = await dialog();
  await answerDialog("取消");
  await until(async () => (await dialog()) === null, "the dialog to close");
  check("leaving with unsaved edits asks first, and 取消 keeps the document and its edit",
    unsaved.title === "放弃未另存的修改？" && (await preview()).includes("# probe note") &&
    (await evaluate("document.querySelector('[data-testid=\"config-visual\"]') !== null")));
  await clickText(".configuration-modes button", "生成新配置");
  await until(async () => (await dialog()) !== null, "the unsaved question again");
  await answerDialog("放弃修改");
  await uiWait("document.querySelector('[data-testid=\"config-generate\"]') !== null", "the generator");
  check("confirming leaves for the generator", true);

  // 12. A quick Nginx draft opens as a tree, byte for byte.
  await evaluate("[...document.querySelectorAll('.config-product-list button')].find((b) => b.textContent.includes('Nginx'))?.click(), true");
  await sleep(200);
  await evaluate("document.querySelector('[data-testid=\"config-generate\"]').click(), true");
  await uiWait("document.querySelector('[data-testid=\"config-artifact-preview-text\"]') !== null", "the quick draft");
  const quickText = await evaluate("document.querySelector('[data-testid=\"config-artifact-preview-text\"]').textContent");
  await evaluate("document.querySelector('[data-testid=\"config-artifact-notes\"] summary')?.click(), true");
  await sleep(150);
  const draftNotes = await textOf("[data-testid=\"config-artifact-notes\"]");
  check("the generated draft lists what each of its directives means in Chinese, beside an unchanged preview",
    /用到的 \d+ 个配置项/u.test(draftNotes) && draftNotes.includes("listen") && draftNotes.includes("站点监听的地址和端口") &&
    !quickText.includes("站点监听的地址和端口") &&
    (await evaluate("document.querySelector('[data-testid=\"config-artifact-notes\"]').open")), draftNotes.slice(0, 300));
  await page.shot("config-generator-notes.png");
  await evaluate("document.querySelector('[data-testid=\"config-open-visual\"]').click(), true");
  await uiWait("document.querySelector('[data-testid=\"config-visual-status\"]')?.textContent.includes('来自快速生成') === true", "the opened draft");
  check("在可视化编辑中打开 turns the quick draft into a tree with exactly its text, in the visual mode",
    (await preview()) === quickText && (await labels()).some((label) => label.startsWith("块 · server")) &&
    (await evaluate("document.querySelector('.configuration-modes .is-active strong')?.textContent")) === "可视化编辑");
  await page.shot("config-visual-from-quick.png");

  // 13. Apache httpd: sections, their closing tags, parts kept as written.
  await clickText(".config-visual-product button", "Apache httpd");
  await clickText(".config-visual-toolbar button", "新建空白文档");
  await uiWait("document.querySelector('[data-testid=\"config-visual-status\"]')?.textContent.startsWith('Apache httpd') === true", "the Apache blank document");
  await evaluate("[...document.querySelectorAll('[data-testid=\"config-visual-add\"] .config-visual-choice label')].find((l) => l.textContent.trim() === '区段').querySelector('input').click(), true");
  await setValue("[data-testid=\"config-visual-add\"] .config-visual-field:nth-of-type(1) input", "Directory");
  await setValue("[data-testid=\"config-visual-add\"] .config-visual-field:nth-of-type(2) input", "/srv/probe");
  await clickText("[data-testid=\"config-visual-add\"] button", "添加区段");
  await until(async () => (await preview())?.includes("<Directory /srv/probe>"), "the Apache section");
  await evaluate("[...document.querySelectorAll('[data-testid=\"config-visual-add\"] .config-visual-choice label')].find((l) => l.textContent.trim() === '指令').querySelector('input').click(), true");
  await evaluate("[...document.querySelectorAll('[data-testid=\"config-visual-add\"] .config-visual-choice label')].find((l) => l.textContent.includes('区段里面'))?.querySelector('input').click(), true");
  await setValue("[data-testid=\"config-visual-add\"] .config-visual-field:nth-of-type(1) input", "Require");
  await setValue("[data-testid=\"config-visual-add\"] .config-visual-field:nth-of-type(2) input", "all denied");
  await clickText("[data-testid=\"config-visual-add\"] button", "添加指令");
  await until(async () => (await preview())?.includes("Require all denied"), "the directive inside the section");
  check("in Apache a section is a 区段, and a directive added inside it lands between its tags, each under its Chinese note",
    /^# 对磁盘上某个目录及其子目录生效的设置。\n<Directory \/srv\/probe>\n {4}# 访问授权条件[^\n]*\n {4}Require all denied\n<\/Directory>/u.test(await preview()) &&
    (await labels()).includes("区段 · Directory · 2 个子项"), await preview());
  await selectRow("区段 · Directory · 2 个子项");
  await sleep(150);
  check("the selected Apache section is explained too",
    (await textOf("[data-testid=\"config-visual-help\"]")).includes("对磁盘上某个目录"));
  await setValue("[data-testid=\"config-visual-selected\"] .config-visual-field:nth-of-type(2) input", "/srv/other");
  await clickText("[data-testid=\"config-visual-selected\"] button", "保存修改");
  await until(async () => (await preview())?.includes("<Directory /srv/other>"), "the edited section");
  check("editing a section's opening line keeps its closing tag and its contents",
    /<Directory \/srv\/other>\n {4}# 访问授权条件[^\n]*\n {4}Require all denied\n<\/Directory>/u.test(await preview()));
  const apacheSaved = path.join(files, "httpd-edited.conf");
  app.setDialogAnswers([apacheSaved]);
  await clickText(".config-visual-toolbar button", "另存为文件");
  await until(async () => (await notice()).includes("apachectl -t"), "the Apache save");
  check("the Apache file saves as shown and points to apachectl -t", fs.readFileSync(apacheSaved, "utf8") === (await preview()));

  const perl = "ServerRoot \"/etc/httpd\"\n<Perl>\nmy $probe = 1;\n</Perl>\nListen 8082\n";
  const perlPath = path.join(files, "perl.conf");
  fs.writeFileSync(perlPath, perl);
  app.setDialogAnswers([perlPath]);
  await clickText(".config-visual-toolbar button", "导入本地文件");
  await until(async () => (await labels()).includes("原文"), "the Perl import");
  check("an embedded <Perl> part is shown as 原文, kept as written, and the rest stays editable",
    (await evaluate("document.querySelector('.config-visual-banners').textContent.includes('Perl')")) &&
    (await labels()).includes("指令 · Listen"));
  const perlCopy = path.join(files, "perl-copy.conf");
  app.setDialogAnswers([perlCopy]);
  await clickText(".config-visual-toolbar button", "另存为文件");
  await until(async () => (await notice()).includes("已另存为"), "the Perl save");
  check("and saves back byte for byte", Buffer.compare(fs.readFileSync(perlCopy), Buffer.from(perl)) === 0);

  const pass = "probe-pass-91ac";
  const passPath = path.join(files, "ssl.conf");
  fs.writeFileSync(passPath, `<VirtualHost *:443>\n    SSLPassPhraseDialog "exec:/usr/local/bin/${pass}"\n</VirtualHost>\n`);
  app.setDialogAnswers([passPath]);
  await clickText(".config-visual-toolbar button", "导入本地文件");
  await until(async () => (await labels()).some((label) => label.startsWith("区段 · VirtualHost")), "the SSL import");
  check("an Apache pass-phrase setting is hidden and its section locked",
    !(await evaluate(`document.body.innerText.includes(${JSON.stringify(pass)})`)) &&
    (await evaluate("document.querySelector('.config-visual-row.is-locked') !== null")));

  // 14. A quick Apache draft opens as a tree too.
  await clickText(".configuration-modes button", "生成新配置");
  await uiWait("document.querySelector('[data-testid=\"config-generate\"]') !== null", "the generator again");
  await evaluate("[...document.querySelectorAll('.config-product-list button')].find((b) => b.textContent.includes('Apache'))?.click(), true");
  await sleep(200);
  await evaluate("document.querySelector('[data-testid=\"config-generate\"]').click(), true");
  await uiWait("document.querySelector('[data-testid=\"config-artifact-preview-text\"]')?.textContent.includes('VirtualHost') === true", "the Apache draft");
  const apacheQuick = await evaluate("document.querySelector('[data-testid=\"config-artifact-preview-text\"]').textContent");
  await evaluate("document.querySelector('[data-testid=\"config-open-visual\"]').click(), true");
  await uiWait("document.querySelector('[data-testid=\"config-visual-status\"]')?.textContent.includes('来自快速生成') === true", "the opened Apache draft");
  check("在可视化编辑中打开 turns a quick Apache draft into a tree of sections with exactly its text",
    (await preview()) === apacheQuick && (await labels()).some((label) => label.startsWith("区段 · VirtualHost")) &&
    (await evaluate("document.querySelector('[data-testid=\"config-visual-status\"] strong').textContent")) === "Apache httpd");
  await page.shot("config-visual-apache.png");

  // 15. Redis: one flat list of lines, explained, with no blocks to add.
  await clickText(".configuration-modes button", "可视化编辑");
  await uiWait("document.querySelector('[data-testid=\"config-visual\"]') !== null", "the visual mode again");
  await clickText(".config-visual-product button", "Redis");
  await clickText(".config-visual-toolbar button, .config-visual-empty-actions button", "新建比赛模板");
  await uiWait("document.querySelector('[data-testid=\"config-visual-status\"]')?.textContent.startsWith('Redis') === true", "the Redis template");
  const redisTemplate = await preview();
  const redisLabels = await labels();
  const redisKinds = await evaluate("[...document.querySelectorAll('[data-testid=\"config-visual-add\"] .config-visual-choice label')].map((l) => l.textContent.trim())");
  check("the Redis template is a flat list of 配置项 with Chinese notes, and offers no blocks or places to nest",
    redisLabels.includes("配置项 · bind") && redisLabels.includes("配置项 · protected-mode") &&
    redisTemplate.includes("protected-mode yes") && !/requirepass/u.test(redisTemplate) &&
    (await evaluate("[...document.querySelectorAll('[data-testid=\"config-visual-row-help\"]')].some((n) => n.textContent.includes('保护模式'))")) &&
    JSON.stringify(redisKinds) === JSON.stringify(["配置项", "注释"]) &&
    (await textOf("[data-testid=\"config-visual-add\"]")).includes("Redis 配置没有块") &&
    (await textOf(".config-visual-banners")).includes("redis-server"), { redisLabels: redisLabels.slice(0, 6), redisKinds });
  await pick("[data-testid=\"config-visual-suggest\"]", "maxclients");
  await sleep(150);
  await clickText("[data-testid=\"config-visual-add\"] button", "添加配置项");
  await until(async () => (await preview())?.includes("maxclients 10000"), "the Redis line");
  check("a picked Redis item is added at the end with its note above it, one line each",
    /\n# 最多同时连接的客户端数量。\nmaxclients 10000\n?$/u.test(await preview()) &&
    (await labels()).at(-1) === "配置项 · maxclients", (await preview()).slice(-200));
  const beforeBroken = await preview();
  await setValue("[data-testid=\"config-visual-add\"] .config-visual-field:nth-of-type(1) input", "maxmemory");
  await setValue("[data-testid=\"config-visual-add\"] .config-visual-field:nth-of-type(2) input", "\"256mb");
  await clickText("[data-testid=\"config-visual-add\"] button", "添加配置项");
  await uiWait("document.querySelector('.config-visual-notice.error') !== null", "the Redis refusal");
  check("a value Redis would not split the same way is refused, note and all", (await preview()) === beforeBroken &&
    (await notice()).includes("没有通过语法检查"));
  const redisPass = "probe-redis-pass-5e2d";
  await setValue("[data-testid=\"config-visual-add\"] .config-visual-field:nth-of-type(1) input", "requirepass");
  await setValue("[data-testid=\"config-visual-add\"] .config-visual-field:nth-of-type(2) input", redisPass);
  await clickText("[data-testid=\"config-visual-add\"] button", "添加配置项");
  await uiWait("document.querySelector('.config-visual-banners')?.textContent.includes('疑似口令') === true", "the hidden password");
  check("a password typed in goes into the file but never back onto the page, and the line is locked",
    !(await evaluate(`document.body.innerText.includes(${JSON.stringify(redisPass)})`)) &&
    (await evaluate("[...document.querySelectorAll('.config-visual-row.is-locked .config-visual-row-label')].some((n) => n.textContent === '配置项 · requirepass')")) &&
    (await evaluate("[...document.querySelectorAll('.config-visual-toolbar button')].find((b) => b.textContent.trim() === '复制全部').disabled")));
  const redisSaved = path.join(files, "redis-edited.conf");
  app.setDialogAnswers([redisSaved]);
  await clickText(".config-visual-toolbar button", "另存为文件");
  await until(async () => (await notice()).includes("已另存为"), "the Redis save");
  const redisBytes = fs.readFileSync(redisSaved, "utf8");
  check("the saved Redis file holds the template, the new lines and the password exactly, and says how to check it",
    redisBytes.startsWith(redisTemplate) && redisBytes.includes("maxclients 10000\n") &&
    new RegExp(`\\n# 默认用户的访问口令。\\nrequirepass ${redisPass}\\n?$`, "u").test(redisBytes) &&
    (await notice()).includes("redis-server"), redisBytes.slice(-300));
  await page.shot("config-visual-redis.png");

  const brokenRedis = "port 6379\nbind \"broken\nmaxmemory 64mb\n";
  const brokenPath = path.join(files, "broken-redis.conf");
  fs.writeFileSync(brokenPath, brokenRedis);
  app.setDialogAnswers([brokenPath]);
  await clickText(".config-visual-toolbar button", "导入本地文件");
  await until(async () => (await labels()).includes("原文"), "the broken Redis import");
  check("a Redis line with an unclosed quote is kept as written; the rest stays editable",
    (await textOf(".config-visual-banners")).includes("引号没有闭合") &&
    (await labels()).includes("配置项 · maxmemory") && (await labels()).includes("配置项 · port"));
  const brokenCopy = path.join(files, "broken-redis-copy.conf");
  app.setDialogAnswers([brokenCopy]);
  await clickText(".config-visual-toolbar button", "另存为文件");
  await until(async () => (await notice()).includes("已另存为"), "the broken Redis save");
  check("and saves back byte for byte", Buffer.compare(fs.readFileSync(brokenCopy), Buffer.from(brokenRedis)) === 0);

  // 16. A quick Redis draft opens as a list too.
  await clickText(".configuration-modes button", "生成新配置");
  await uiWait("document.querySelector('[data-testid=\"config-generate\"]') !== null", "the generator for Redis");
  await evaluate("[...document.querySelectorAll('.config-product-list button')].find((b) => b.textContent.includes('Redis'))?.click(), true");
  await sleep(200);
  await evaluate("document.querySelector('[data-testid=\"config-generate\"]').click(), true");
  await uiWait("document.querySelector('[data-testid=\"config-artifact-preview-text\"]')?.textContent.includes('maxmemory') === true", "the Redis draft");
  const redisQuick = await evaluate("document.querySelector('[data-testid=\"config-artifact-preview-text\"]').textContent");
  await evaluate("document.querySelector('[data-testid=\"config-open-visual\"]').click(), true");
  await uiWait("document.querySelector('[data-testid=\"config-visual-status\"]')?.textContent.includes('来自快速生成') === true", "the opened Redis draft");
  check("在可视化编辑中打开 turns a quick Redis draft into a list with exactly its text",
    (await preview()) === redisQuick && (await labels()).some((label) => label.startsWith("配置项 · ")) &&
    (await evaluate("document.querySelector('[data-testid=\"config-visual-status\"] strong').textContent")) === "Redis");

  // 17. HAProxy: sections named by a keyword, settings only inside them.
  await clickText(".config-visual-product button", "HAProxy");
  await clickText(".config-visual-toolbar button", "新建比赛模板");
  await uiWait("document.querySelector('[data-testid=\"config-visual-status\"]')?.textContent.startsWith('HAProxy') === true", "the HAProxy template");
  const haproxyTemplate = await preview();
  const haproxyLabels = await labels();
  check("the HAProxy template shows its sections with their lines and Chinese notes, and comments in the file",
    haproxyLabels.includes("区段 · frontend · 4 个子项") && haproxyLabels.includes("区段 · global · 7 个子项") &&
    haproxyTemplate.includes("# 对外入口：监听 80 端口") &&
    (await evaluate("[...document.querySelectorAll('[data-testid=\"config-visual-row-help\"]')].some((n) => n.textContent.includes('对外入口'))")) &&
    (await textOf(".config-visual-banners")).includes("haproxy -c -f"), haproxyLabels.slice(0, 8));
  await addKind("指令");
  await sleep(100);
  check("with nothing selected a setting has nowhere to go, and the page says to pick a section",
    (await textOf("[data-testid=\"config-visual-add-place\"]")).includes("必须写在区段里") &&
    (await evaluate("[...document.querySelectorAll('[data-testid=\"config-visual-add\"] button')].find((b) => b.textContent.startsWith('添加指令')).disabled")));
  await selectRow("指令 · server");
  await sleep(150);
  await pick("[data-testid=\"config-visual-suggest\"]", "retries");
  await sleep(150);
  const backendOffer = await evaluate("[...document.querySelectorAll('[data-testid=\"config-visual-suggest\"] option')].map((o) => o.value)");
  check("a selected line stands for its section, and the list offers what a backend takes",
    (await textOf("[data-testid=\"config-visual-add-place\"]")).includes("加在 backend app 区段的最后") &&
    backendOffer.includes("server") && backendOffer.includes("balance") && !backendOffer.includes("bind"),
    backendOffer.slice(0, 12));
  await clickText("[data-testid=\"config-visual-add\"] button", "添加指令");
  await until(async () => (await preview())?.includes("retries 3"), "the HAProxy setting");
  check("the setting goes at the end of that section, indented, under its Chinese note",
    /\n {4}server app1 127\.0\.0\.1:8080 check\n {4}# 连接后端失败后重试几次。\n {4}retries 3\n$/u.test(await preview()),
    (await preview()).slice(-200));
  await addKind("区段");
  await sleep(100);
  await pick("[data-testid=\"config-visual-suggest\"]", "listen");
  await sleep(150);
  check("a new section always goes at the top level: the page says so instead of offering a place",
    (await textOf("[data-testid=\"config-visual-add\"]")).includes("区段不能嵌套") &&
    (await valueOf("[data-testid=\"config-visual-add\"] .config-visual-field:nth-of-type(2) input")) === "stats");
  await clickText("[data-testid=\"config-visual-add\"] button", "添加区段");
  await until(async () => (await preview())?.includes("listen stats"), "the HAProxy section");
  check("the section and its note land at the end of the file, the note shown above it at the top level",
    /\n# 入口和后端合在一起的写法[^\n]*\nlisten stats\n?$/u.test(await preview()) &&
    (await labels()).includes("区段 · listen") &&
    (await evaluate("document.querySelector('.config-visual-row.is-selected .config-visual-row-label')?.textContent")) === "区段 · listen",
    (await preview()).slice(-200));
  const haproxyPass = "probe-haproxy-pass-7b31";
  await addKind("指令");
  await setValue("[data-testid=\"config-visual-add\"] .config-visual-field:nth-of-type(1) input", "stats");
  await setValue("[data-testid=\"config-visual-add\"] .config-visual-field:nth-of-type(2) input", `auth admin:${haproxyPass}`);
  await clickText("[data-testid=\"config-visual-add\"] button", "添加指令");
  await uiWait("document.querySelector('.config-visual-banners')?.textContent.includes('疑似口令') === true", "the hidden stats password");
  check("stats auth goes into the file but its password never comes back onto the page",
    !(await evaluate(`document.body.innerText.includes(${JSON.stringify(haproxyPass)})`)) &&
    (await evaluate("[...document.querySelectorAll('.config-visual-row.is-locked .config-visual-row-label')].some((n) => n.textContent === '指令 · stats')")));
  const haproxySaved = path.join(files, "haproxy-edited.cfg");
  app.setDialogAnswers([haproxySaved]);
  await clickText(".config-visual-toolbar button", "另存为文件");
  await until(async () => (await notice()).includes("已另存为"), "the HAProxy save");
  const haproxyBytes = fs.readFileSync(haproxySaved, "utf8");
  check("the saved HAProxy file is the template plus exactly the new lines, and the notice names haproxy -c",
    haproxyBytes.startsWith(haproxyTemplate.slice(0, haproxyTemplate.indexOf("    server app1"))) &&
    haproxyBytes.includes("    retries 3\n") &&
    new RegExp(`\\nlisten stats\\n {4}# [^\\n]+\\n {4}stats auth admin:${haproxyPass}\\n?$`, "u").test(haproxyBytes) &&
    (await notice()).includes("haproxy -c -f"), haproxyBytes.slice(-300));
  await page.shot("config-visual-haproxy.png");

  const odd = "maxconn 10\nglobal\n    .if defined(PROBE)\n    daemon\n    .endif\nfrontend web # main\n    bind :80\n";
  const oddPath = path.join(files, "odd-haproxy.cfg");
  fs.writeFileSync(oddPath, odd);
  app.setDialogAnswers([oddPath]);
  await clickText(".config-visual-toolbar button", "导入本地文件");
  await until(async () => (await labels()).includes("原文"), "the odd HAProxy import");
  check("a setting outside any section and .if lines are kept as written; a trailing comment stays out of the name",
    (await textOf(".config-visual-banners")).includes(".if") &&
    (await labels()).includes("区段 · frontend · 1 个子项") && (await labels()).includes("指令 · daemon"));
  const oddCopy = path.join(files, "odd-haproxy-copy.cfg");
  app.setDialogAnswers([oddCopy]);
  await clickText(".config-visual-toolbar button", "另存为文件");
  await until(async () => (await notice()).includes("已另存为"), "the odd HAProxy save");
  check("and saves back byte for byte", Buffer.compare(fs.readFileSync(oddCopy), Buffer.from(odd)) === 0);

  // 18. A quick HAProxy draft: its notes, then opened as sections.
  await clickText(".configuration-modes button", "生成新配置");
  await uiWait("document.querySelector('[data-testid=\"config-generate\"]') !== null", "the generator for HAProxy");
  await evaluate("[...document.querySelectorAll('.config-product-list button')].find((b) => b.textContent.includes('HAProxy'))?.click(), true");
  await sleep(200);
  await evaluate("document.querySelector('[data-testid=\"config-generate\"]').click(), true");
  await uiWait("document.querySelector('[data-testid=\"config-artifact-preview-text\"]')?.textContent.includes('frontend') === true", "the HAProxy draft");
  const haproxyQuick = await evaluate("document.querySelector('[data-testid=\"config-artifact-preview-text\"]').textContent");
  check("the HAProxy draft lists what each keyword means",
    (await textOf("[data-testid=\"config-artifact-notes\"]")).includes("对外入口"));
  await evaluate("document.querySelector('[data-testid=\"config-open-visual\"]').click(), true");
  await uiWait("document.querySelector('[data-testid=\"config-visual-status\"]')?.textContent.includes('来自快速生成') === true", "the opened HAProxy draft");
  check("在可视化编辑中打开 turns a quick HAProxy draft into sections with exactly its text and nothing unreadable",
    (await preview()) === haproxyQuick && (await labels()).some((label) => label.startsWith("区段 · frontend")) &&
    !(await labels()).includes("原文") &&
    (await evaluate("document.querySelector('[data-testid=\"config-visual-status\"] strong').textContent")) === "HAProxy");

  // 16. A stale Apache document, with an unsaved edit, is replaced by an
  // imported Nginx file (the legacy nginx_import_result_replaces_a_stale_apache_visual_document).
  const status = () => evaluate("(() => { const s = document.querySelector('[data-testid=\"config-visual-status\"]'); return s ? { product: s.querySelector('strong')?.textContent ?? '', source: s.querySelector('span')?.textContent ?? '' } : null; })()");
  await clickText(".config-visual-product button", "Apache httpd");
  await clickText(".config-visual-toolbar button", "新建比赛模板");
  await until(async () => (await status())?.product === "Apache httpd" && (await status())?.source === "比赛模板", "the Apache template");
  await addKind("指令");
  await evaluate("[...document.querySelectorAll('[data-testid=\"config-visual-add\"] .config-visual-choice label')].find((l) => l.textContent.includes('最外层'))?.querySelector('input').click(), true");
  await setValue("[data-testid=\"config-visual-add\"] .config-visual-field:nth-of-type(1) input", "ServerTokens");
  await setValue("[data-testid=\"config-visual-add\"] .config-visual-field:nth-of-type(2) input", "Prod");
  await clickText("[data-testid=\"config-visual-add\"] button", "添加指令");
  await until(async () => (await dirty()) && (await preview())?.includes("ServerTokens Prod"), "the unsaved Apache edit");
  const apacheText = await preview();
  const importBytes = "events {}\nhttp { server { listen 80; } }\n";
  const importPath = path.join(files, "nginx.conf");
  fs.writeFileSync(importPath, importBytes);
  await clickText(".config-visual-product button", "Nginx");
  app.setDialogAnswers([importPath]);
  await clickText(".config-visual-toolbar button", "导入本地文件");
  await until(async () => (await dialog()) !== null, "the discard question");
  const discardAsked = await dialog();
  await answerDialog("取消");
  await until(async () => (await dialog()) === null, "the question to close");
  const keptApache = { status: await status(), dirty: await dirty(), same: (await preview()) === apacheText, answersLeft: app.dialogAnswersLeft().length };
  await clickText(".config-visual-toolbar button", "导入本地文件");
  await until(async () => (await dialog()) !== null, "the discard question again");
  await answerDialog("放弃修改");
  await until(async () => (await status())?.product === "Nginx", "the imported Nginx document");
  const replacedByNginx = { status: await status(), dirty: await dirty(), exact: (await preview()) === importBytes, notice: await notice(),
    answersLeft: app.dialogAnswersLeft().length, labels: await labels(), mode: await textOf(".configuration-modes button[aria-pressed=\"true\"]") };
  await evaluate("document.querySelector('.content')?.scrollTo(0, 0), true");
  await page.shot("nginx-import-replaced-apache.png");
  check("an imported Nginx file replaces a stale Apache document only after unsaved edits are given up, byte for byte and clean",
    discardAsked?.title === "放弃未另存的修改？" &&
      keptApache.status?.product === "Apache httpd" && keptApache.dirty && keptApache.same && keptApache.answersLeft === 1 &&
      replacedByNginx.status?.product === "Nginx" && replacedByNginx.status?.source === "导入的文件" && !replacedByNginx.dirty && replacedByNginx.exact &&
      replacedByNginx.notice.includes("已导入本地文件") && replacedByNginx.answersLeft === 0 && replacedByNginx.mode.trim() === "可视化编辑" &&
      replacedByNginx.labels.some((label) => label.startsWith("块 · http")),
    { discardAsked, keptApache, replacedByNginx });

  // 17. A MySQL option file from the template: groups of options, each explained.
  const clickRowStarting = (prefix) => evaluate(`(() => { const b = [...document.querySelectorAll('.config-visual-row')].find((x) => x.querySelector('.config-visual-row-label').textContent.startsWith(${JSON.stringify(prefix)})); if (!b) throw new Error('no row ' + ${JSON.stringify(prefix)}); b.click(); return true; })()`);
  const addButton = () => evaluate("(() => { const b = [...document.querySelectorAll('[data-testid=\"config-visual-add\"] button[type=submit]')][0]; return b ? { text: b.textContent.trim(), disabled: b.disabled } : null; })()");
  await clickText(".config-visual-product button", "MySQL");
  await clickText(".config-visual-toolbar button", "新建比赛模板");
  await uiWait("document.querySelector('[data-testid=\"config-visual-status\"] strong')?.textContent === 'MySQL'", "the MySQL template");
  await sleep(300);
  const mysqlTemplate = {
    text: await preview(), status: await status(),
    unexplained: await evaluate("[...document.querySelectorAll('.config-visual-row[data-kind=\"directive\"], .config-visual-row[data-kind=\"block\"]')].filter((row) => !row.querySelector('[data-testid=\"config-visual-row-help\"]')).map((row) => row.querySelector('.config-visual-row-label').textContent)"),
    groups: (await labels()).filter((label) => label.startsWith("选项组")),
  };
  await addKind("选项");
  const needsGroup = { hint: await textOf("[data-testid=\"config-visual-add-place\"]"), button: await addButton() };
  await clickRowStarting("选项组 · mysqld");
  await pick("[data-testid=\"config-visual-suggest\"]", "require_secure_transport");
  const pickedOption = { name: await valueOf("[data-testid=\"config-visual-add\"] .config-visual-field:nth-of-type(1) input"),
    note: await valueOf("[data-testid=\"config-visual-note-text\"]") };
  await clickText("[data-testid=\"config-visual-add\"] button", "添加选项");
  await until(async () => (await preview())?.includes("require_secure_transport=ON"), "the added option");
  const afterOption = await preview();
  // An include line with nothing selected goes before the first group.
  await clickRowStarting("选项组 · mysqld");
  await clickRowStarting("选项组 · mysqld");
  await setValue("[data-testid=\"config-visual-add\"] .config-visual-field:nth-of-type(1) input", "!includedir");
  await setValue("[data-testid=\"config-visual-add\"] .config-visual-field:nth-of-type(2) input", "/etc/mysql/conf.d/");
  const includeHint = await textOf("[data-testid=\"config-visual-add-place\"]");
  await clickText("[data-testid=\"config-visual-add\"] button", "添加选项");
  await until(async () => (await preview())?.includes("!includedir /etc/mysql/conf.d/"), "the include line");
  const afterInclude = await preview();
  // Change a value in place.
  await clickRowStarting("选项 · bind-address");
  await setValue("[data-testid=\"config-visual-selected\"] .config-visual-field:nth-of-type(2) input", "10.0.0.5");
  await clickText("[data-testid=\"config-visual-selected\"] button", "保存修改");
  await until(async () => (await preview())?.includes("bind-address=10.0.0.5"), "the changed value");
  // A group has no arguments to edit.
  await clickRowStarting("选项组 · client");
  const groupEditor = { fields: await evaluate("document.querySelectorAll('[data-testid=\"config-visual-selected\"] .config-visual-field').length"),
    hint: await textOf("[data-testid=\"config-visual-selected\"] .config-visual-hint") };
  const onScreenMysql = await preview();
  const mysqlPath = path.join(files, "my.cnf");
  app.setDialogAnswers([mysqlPath]);
  await clickText(".config-visual-toolbar button", "另存为文件");
  await until(() => fs.existsSync(mysqlPath), "the saved option file");
  await until(async () => !(await dirty()), "the unsaved mark to clear");
  const mysqlSavedNotice = await notice();
  await page.shot("mysql-option-file.png");
  check("a MySQL option file is edited as groups of explained options: options need a group, includes go first, groups have no arguments",
    mysqlTemplate.status?.source === "比赛模板" && mysqlTemplate.text?.startsWith("# LovelyHawk 应急响应比赛 MySQL 选项文件骨架") &&
      mysqlTemplate.unexplained.length === 0 && mysqlTemplate.groups.length === 2 &&
      needsGroup.hint.includes("选项必须写在选项组里") && needsGroup.button?.disabled === true && needsGroup.button?.text === "添加选项" &&
      pickedOption.name === "require_secure_transport" && pickedOption.note === "只接受加密（TLS）连接或本机套接字连接。" &&
      afterOption.includes("# 只接受加密（TLS）连接或本机套接字连接。\nrequire_secure_transport=ON\n") &&
      afterOption.indexOf("require_secure_transport=ON") < afterOption.indexOf("[client]") &&
      includeHint.includes("文件开头") &&
      /# 读取这个目录里所有 \.cnf 文件[^\n]*\n!includedir \/etc\/mysql\/conf\.d\/\n\[mysqld\]/u.test(afterInclude) &&
      groupEditor.fields === 1 && groupEditor.hint.includes("选项组只有组名") &&
      fs.readFileSync(mysqlPath, "utf8") === onScreenMysql && mysqlSavedNotice.includes("--validate-config"),
    { mysqlTemplate: { ...mysqlTemplate, text: mysqlTemplate.text?.slice(0, 60) }, needsGroup, pickedOption, includeHint, groupEditor, mysqlSavedNotice,
      savedSame: fs.existsSync(mysqlPath) && fs.readFileSync(mysqlPath, "utf8") === onScreenMysql });

  // 19. A catalogued database file: its reviewed starting content, read
  // against a chosen version, one value written through the catalogue.
  const catalogTags = () => evaluate("document.querySelectorAll('[data-testid=\"config-visual-row-catalog\"]').length");
  const parameterButton = (key) => evaluate(`(() => { const b = [...document.querySelectorAll('.config-visual-parameter-list button')].find((x) => x.querySelector('.config-visual-parameter-key').textContent === ${JSON.stringify(key)}); if (!b) throw new Error('no parameter ' + ${JSON.stringify(key)}); b.click(); return true; })()`);
  await clickText(".config-visual-product button", "数据库配置文件");
  await uiWait("document.querySelector('[data-testid=\"config-visual-database-product\"]') !== null", "the database file picker");
  const catalogProducts = await evaluate("[...document.querySelectorAll('[data-testid=\"config-visual-database-product\"] option')].map((o) => o.value)");
  await pick("[data-testid=\"config-visual-database-product\"]", "postgresql");
  await pick("[data-testid=\"config-visual-database-file\"]", "postgresql-main");
  await uiWait("document.querySelector('[data-testid=\"config-visual-database-open\"]')?.textContent === '打开起始内容'", "a draftable file");
  await evaluate("document.querySelector('[data-testid=\"config-visual-database-open\"]').click(), true");
  await uiWait("document.querySelector('[data-testid=\"config-visual-status\"] strong')?.textContent.startsWith('PostgreSQL')", "the PostgreSQL starter");
  const starter = { status: await status(), text: await preview(), tags: await catalogTags(), dirty: await dirty(),
    parameters: await evaluate("document.querySelector('[data-testid=\"config-visual-parameters\"]') !== null"),
    labels: await labels() };
  const v16 = await evaluate("[...document.querySelectorAll('[data-testid=\"config-visual-schema\"] option')].find((o) => o.textContent.startsWith('PostgreSQL 16.x'))?.value ?? null");
  if (v16 === null) throw new Error("no PostgreSQL 16 catalogue to read against");
  await pick("[data-testid=\"config-visual-schema\"]", v16);
  await until(async () => (await catalogTags()) > 0, "rows the catalogue describes");
  const chosen = { text: await preview(), tags: await catalogTags(), dirty: await dirty(), notice: await notice(),
    heading: await textOf("[data-testid=\"config-visual-parameters\"] h2") };
  await clickRowStarting("配置项 · listen_addresses");
  const rowDetail = await textOf("[data-testid=\"config-visual-selected\"] [data-testid=\"config-visual-help\"]");
  // The tree is searched by the words a row was given, never by its value.
  await setValue("[data-testid=\"config-visual\"] .config-visual-tree input[type=search]", "localhost");
  await sleep(200);
  const byValue = await labels();
  await setValue("[data-testid=\"config-visual\"] .config-visual-tree input[type=search]", "listen_addresses");
  await sleep(200);
  const byName = await labels();
  await setValue("[data-testid=\"config-visual\"] .config-visual-tree input[type=search]", "");
  await setValue("[data-testid=\"config-visual-parameter-search\"]", "max_connections");
  await sleep(200);
  await parameterButton("max_connections");
  await uiWait("document.querySelector('[data-testid=\"config-visual-parameter-value\"]') !== null", "the value field");
  const parameterDetail = await textOf("[data-testid=\"config-visual-parameter-detail\"]");
  const valueLabel = await textOf("[data-testid=\"config-visual-parameters\"] .config-visual-parameter-set .config-visual-field span");
  await setValue("[data-testid=\"config-visual-parameter-value\"]", "250");
  await evaluate("document.querySelector('[data-testid=\"config-visual-parameter-apply\"]').click(), true");
  await until(async () => (await preview())?.includes("max_connections = 250"), "the written value");
  const firstWrite = { text: await preview(), notice: await notice(), dirty: await dirty(),
    facts: await textOf(".config-visual-parameter-list button.is-selected .config-visual-parameter-facts") };
  await until(async () => (await valueOf("[data-testid=\"config-visual-parameter-value\"]")) === "", "the value field to clear");
  await setValue("[data-testid=\"config-visual-parameter-value\"]", "300");
  await evaluate("document.querySelector('[data-testid=\"config-visual-parameter-apply\"]').click(), true");
  await until(async () => (await preview())?.includes("max_connections = 300"), "the replaced value");
  const secondWrite = await preview();
  await until(async () => (await valueOf("[data-testid=\"config-visual-parameter-value\"]")) === "", "the value field to clear");
  await setValue("[data-testid=\"config-visual-parameter-value\"]", "x".repeat(33));
  await evaluate("document.querySelector('[data-testid=\"config-visual-parameter-apply\"]').click(), true");
  await uiWait("document.querySelector('.config-visual-notice.error') !== null", "the refusal");
  const refused = { notice: await notice(), same: (await preview()) === secondWrite };
  await page.shot("database-file.png");
  const pgPath = path.join(files, "postgresql.conf");
  app.setDialogAnswers([pgPath]);
  await clickText(".config-visual-toolbar button", "另存为文件");
  await until(() => fs.existsSync(pgPath), "the saved PostgreSQL file");
  await until(async () => !(await dirty()), "the unsaved mark to clear");
  check("a catalogued PostgreSQL file opens from reviewed content, reads against a chosen version and takes values only through the catalogue",
    catalogProducts.includes("postgresql") && starter.status?.source === "起始内容" &&
      starter.text?.includes("listen_addresses = 'localhost'") && starter.tags === 0 && !starter.dirty && !starter.parameters &&
      starter.labels.includes("配置项 · listen_addresses") &&
      chosen.text === starter.text && chosen.tags > 0 && !chosen.dirty && chosen.notice.includes("没有核对过任何服务器") &&
      /^目录里的参数（\d+）$/u.test(chosen.heading) && rowDetail.includes("以上来自内置目录") &&
      byValue.length === 0 && byName.some((label) => label.startsWith("配置项 · listen_addresses")) &&
      parameterDetail.includes("以上来自内置目录") && valueLabel.includes("会新加一行") &&
      firstWrite.notice.includes("已把 max_connections 写入草稿") && firstWrite.dirty && firstWrite.facts.startsWith("文件里有 1 处") &&
      secondWrite.includes("max_connections = 300") && !secondWrite.includes("250") && secondWrite.match(/max_connections/gu)?.length === 1 &&
      refused.notice.includes("不符合所选版本目录") && refused.same &&
      fs.readFileSync(pgPath, "utf8") === secondWrite,
    { catalogProducts, starter: { ...starter, text: starter.text?.slice(0, 80) }, chosen: { ...chosen, text: undefined }, rowDetail: rowDetail.slice(0, 80),
      byValue, byName, parameterDetail: parameterDetail.slice(0, 80), valueLabel, firstWrite: { ...firstWrite, text: undefined }, refused });

  // 20. A file the server writes itself: read and kept, never changed here.
  await pick("[data-testid=\"config-visual-database-file\"]", "postgresql-auto-conf");
  await uiWait("document.querySelector('[data-testid=\"config-visual-database-open\"]')?.textContent === '打开（只读）'", "a read-only file");
  const autoPath = path.join(files, "postgresql.auto.conf");
  const autoText = "# Do not edit this file manually!\n# It will be overwritten by the ALTER SYSTEM command.\nmax_connections = '200'\n";
  fs.writeFileSync(autoPath, autoText);
  app.setDialogAnswers([autoPath]);
  await clickText(".config-visual-toolbar button", "导入本地文件");
  await uiWait("document.querySelector('[data-testid=\"config-visual-status\"] span')?.textContent === '导入的文件'", "the imported auto file");
  await sleep(300);
  const autoView = { status: await status(), same: (await preview()) === autoText, labels: await labels(),
    readOnly: await textOf("[data-testid=\"config-visual-database\"] .is-blocking"),
    add: await textOf("[data-testid=\"config-visual-add\"]"),
    addKinds: await evaluate("document.querySelectorAll('[data-testid=\"config-visual-add\"] input').length") };
  await clickRowStarting("配置项 · max_connections");
  const autoSelected = { inputs: await evaluate("document.querySelectorAll('[data-testid=\"config-visual-selected\"] input').length"),
    save: await evaluate("[...document.querySelectorAll('[data-testid=\"config-visual-selected\"] button')].some((b) => b.textContent.includes('保存修改'))") };
  const autoCopy = path.join(files, "postgresql.auto.copy.conf");
  app.setDialogAnswers([autoCopy]);
  await clickText(".config-visual-toolbar button", "另存为文件");
  await until(() => fs.existsSync(autoCopy), "the saved copy");
  await page.shot("database-file-read-only.png");
  check("a server-written PostgreSQL file imports read-only: nothing to add or change, and its copy is byte for byte",
    autoView.status?.product.startsWith("PostgreSQL") && autoView.same && autoView.labels.some((label) => label.startsWith("配置项 · max_connections")) &&
      autoView.readOnly.includes("由服务器或厂商工具生成") && autoView.add.includes("这个文件只读") && autoView.addKinds === 0 &&
      autoSelected.inputs === 0 && !autoSelected.save && fs.readFileSync(autoCopy, "utf8") === autoText &&
      app.dialogAnswersLeft().length === 0,
    { autoView, autoSelected });
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
  schema: "lovelyhawk-config-visual-probe/v1",
  status: failures === 0 ? "PASS" : "FAIL",
  generatedAt: new Date().toISOString(),
  checks,
}, null, 2)}\n`);
console.log(`${failures === 0 ? "PASS" : "FAIL"}: ${checks.filter((item) => item.passed).length}/${checks.length}; evidence in ${evidence}`);
process.exitCode = failures === 0 ? 0 : 1;
