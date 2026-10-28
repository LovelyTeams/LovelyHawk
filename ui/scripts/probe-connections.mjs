// Saved connections under the Tauri shell, in the real window, with no SSH
// target involved: the empty manager, creating connections with a password,
// search, export through the host's save dialog (secret-free, create-new only,
// cancellable), the two-step permanent delete, import through the host's open
// dialog (duplicates reported, malformed / oversized / too-many files refused
// without partial writes) and persistence across a restart.
//
// The two OS dialogs are answered by the debug-only scripted answers file;
// everything after the dialog — the backend call, its checks and its
// response — runs as it does for an operator. Throwaway data root; the hosts
// below are documentation addresses (192.0.2.0/24) and are never contacted.

import { randomUUID } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { attach, delay, launchDesktop, waitFor } from "./cdp.mjs";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const executable = path.join(repositoryRoot, "target", "debug", process.platform === "win32" ? "lovelyhawk.exe" : "lovelyhawk");
const runRoot = path.join(repositoryRoot, "target", "desktop-debug", `connections-${randomUUID()}`);
const evidence = path.join(runRoot, "evidence");
const files = path.join(runRoot, "files");
const answersFile = path.join(runRoot, "dialog-answers.json");
const secret = `Probe-Secret-${randomUUID()}`;
const exportPath = path.join(files, "connections-export.json");
const checks = [];
function check(name, ok, detail = null) {
  checks.push({ name, ok: Boolean(ok), detail });
  console.log(`${ok ? "PASS" : "FAIL"} ${name}${detail === null ? "" : ` — ${JSON.stringify(detail)}`}`);
}

fs.mkdirSync(evidence, { recursive: true });
fs.mkdirSync(files, { recursive: true });
const answer = (...answers) => fs.writeFileSync(answersFile, JSON.stringify(answers));
answer();

async function run(phase, scenario) {
  const port = 10_300 + Math.floor(Math.random() * 200);
  const { child, output } = launchDesktop({
    executable,
    archiveRoot: runRoot,
    port,
    extraEnv: { LOVELYHAWK_TEST_DIALOG_ANSWERS: answersFile },
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
    await waitFor(() => session.evaluate("document.querySelector('[data-testid=\"open-connections\"]') !== null"), { label: "the title bar" });
    await session.evaluate("document.querySelector('[data-testid=\"open-connections\"]').click(), true");
    await waitFor(() => session.evaluate("document.querySelector('.connection-manager') !== null && !(document.querySelector('.connection-sidebar-meta span')?.textContent ?? '').includes('读取中')"), { timeoutMs: 20_000, label: "the connection manager" });
    await scenario(session);
    check(`${phase}: the page never holds the saved password`, !(await session.evaluate("document.documentElement.outerHTML")).includes(secret));
    check(`${phase}: no console errors`, errors.length === 0, errors.slice(0, 3));
    await session.evaluate("document.querySelector('[aria-label=\"关闭连接管理\"]')?.click(), true");
    await delay(500);
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

const state = `({
  count: Number((document.querySelector('.connection-sidebar-meta strong')?.textContent ?? '').replace(/\\D+/gu, '') || -1),
  rows: [...document.querySelectorAll('.connection-list .connection-list-row strong')].map((row) => row.textContent),
  empty: document.querySelector('.connection-list-empty')?.textContent ?? null,
  detailEmpty: document.querySelector('.connection-detail-empty h2')?.textContent ?? null,
  notice: document.querySelector('.connection-notice:not(.error)')?.textContent ?? null,
  error: document.querySelector('.connection-notice.error')?.textContent ?? null,
  detail: document.querySelector('.connection-details-view h2')?.textContent ?? null,
  credential: [...document.querySelectorAll('.connection-fact-grid > div')].find((fact) => fact.querySelector('span')?.textContent === '凭据状态')?.querySelector('strong')?.textContent ?? null,
})`;
const until = (session, predicate, label, timeoutMs = 10_000) =>
  waitFor(async () => { const value = await session.evaluate(state); return predicate(value) ? value : null; }, { timeoutMs, label }).catch(async () => session.evaluate(state));
const clickText = (selector, text) => `(() => {
  const element = [...document.querySelectorAll(${JSON.stringify(selector)})].find((candidate) => candidate.textContent.trim() === ${JSON.stringify(text)});
  if (!element || element.disabled) return false;
  element.click();
  return true;
})()`;
const setField = (label, value) => `(() => {
  const field = [...document.querySelectorAll('.connection-editor .connection-field')].find((candidate) => candidate.querySelector('span')?.textContent.startsWith(${JSON.stringify(label)}));
  const input = field?.querySelector('input, textarea');
  if (!input) return false;
  const prototype = input instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
  Object.getOwnPropertyDescriptor(prototype, 'value').set.call(input, ${JSON.stringify(value)});
  input.dispatchEvent(new Event('input', { bubbles: true }));
  return true;
})()`;
// Rows are disabled while the previous selection loads; a click then does nothing.
const selectRow = (session, name) => waitFor(() => session.evaluate(`(() => {
  const row = [...document.querySelectorAll('.connection-list .connection-list-row')].find((candidate) => candidate.querySelector('strong')?.textContent === ${JSON.stringify(name)});
  if (!row || row.disabled) return false;
  row.click();
  return true;
})()`), { timeoutMs: 10_000, label: `the ${name} row` });
const search = (value) => `(() => {
  const input = document.querySelector('input[aria-label="搜索连接"]');
  Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(input, ${JSON.stringify(value)});
  input.dispatchEvent(new Event('input', { bubbles: true }));
  return true;
})()`;

async function create(session, { name, host, password, tags }) {
  await session.evaluate(clickText(".connection-manager-header button", "新建连接"));
  await waitFor(() => session.evaluate("document.querySelector('.connection-editor') !== null"), { timeoutMs: 10_000, label: "the editor" });
  const filled = [
    await session.evaluate(setField("连接名称", name)),
    await session.evaluate(setField("主机名或 IP", host)),
    await session.evaluate(setField("标签", tags ?? "")),
  ];
  // Without a password the connection asks the server at connect time.
  filled.push(password === undefined
    ? await session.evaluate(clickText(".connection-editor .auth-picker button", "交互认证 / MFA"))
    : await session.evaluate(setField("SSH 密码", password)));
  await session.evaluate("document.querySelector('.connection-editor button[type=\"submit\"]').click(), true");
  const now = await until(session, (value) => value.notice === "连接已写入便携加密存储。" && value.detail === name, `saving ${name}`);
  return { filled: filled.every(Boolean), now };
}

await run("first launch", async (session) => {
  let now = await session.evaluate(state);
  check("an empty manager says so in the list and the detail", now.count === 0 && now.empty === "还没有保存的连接。点上方“新建连接”填写主机与账号，或“导入 JSON”。" && now.detailEmpty === "选择或新建连接", now);

  const first = await create(session, { name: "实验 A", host: "192.0.2.10", password: secret, tags: "probe, web" });
  check("a connection with a password is saved and shown with its credential state", first.filled && first.now.count === 1 && first.now.credential === "密码已保存", first.now);
  check("the password left the form once it was saved", await session.evaluate("document.querySelector('.connection-editor') === null && [...document.querySelectorAll('input[type=\"password\"]')].every((input) => input.value === '')"));
  const second = await create(session, { name: "实验 B", host: "192.0.2.11", tags: "probe, db" });
  check("a second connection, without a stored secret, is listed", second.filled && second.now.count === 2 && second.now.credential === "连接时交互输入", second.now);

  await session.evaluate(search("192.0.2.11"));
  now = await until(session, (value) => value.rows.length === 1, "the host search");
  check("search narrows the list by host", now.rows.length === 1 && now.rows[0] === "实验 B", now.rows);
  await session.evaluate(search("zz-none-zz"));
  now = await until(session, (value) => value.rows.length === 0, "the empty search");
  check("a search with no match says so", now.empty === "没有匹配的连接，换个名称、主机或标签试试。", now.empty);
  await session.evaluate(search(""));
  await until(session, (value) => value.rows.length === 2, "the full list");
  await waitFor(() => session.evaluate(clickText(".connection-manager-header button", "刷新")), { timeoutMs: 10_000, label: "刷新" });
  await delay(300);
  now = await until(session, (value) => value.count === 2 && value.rows.length === 2 && value.error === null, "the refreshed list");
  check("刷新 reads the list again and keeps both connections", now.count === 2 && now.rows.length === 2 && now.error === null, now.rows);

  // Export: cancelled, then written, then refused over the same file.
  answer(null);
  await session.evaluate("document.querySelector('[data-testid=\"connection-export\"]').click(), true");
  now = await until(session, (value) => value.notice === "连接导出已取消。", "the cancelled export");
  check("cancelling the save dialog writes nothing", now.notice === "连接导出已取消。" && !fs.existsSync(exportPath), now.notice);
  answer(exportPath);
  await session.evaluate("document.querySelector('[data-testid=\"connection-export\"]').click(), true");
  now = await until(session, (value) => value.notice?.startsWith("已导出 2 个连接") === true, "the export");
  const exported = fs.existsSync(exportPath) ? fs.readFileSync(exportPath, "utf8") : "";
  check("export writes both connections to the chosen file", now.notice === "已导出 2 个连接到 connections-export.json。" && exported.includes("192.0.2.10") && exported.includes("192.0.2.11"), now.notice);
  // A secret would be a value or an encrypted field; "password" as the auth method is not one.
  check("the exported file holds no secret, encrypted or not", exported.length > 0 && !exported.includes(secret) &&
    !/"(?:encrypted_[a-z_]*|password|key_passphrase|jump_host_password|ciphertext)"\s*:|enc:v\d/u.test(exported));
  const before = fs.readFileSync(exportPath);
  answer(exportPath);
  await session.evaluate("document.querySelector('[data-testid=\"connection-export\"]').click(), true");
  now = await until(session, (value) => value.error !== null, "the refused overwrite");
  check("exporting over an existing file is refused in plain words and leaves it untouched", now.error === "所选文件已存在。导出只创建新文件，请换一个文件名。" && fs.readFileSync(exportPath).equals(before), now.error);

  // Permanent delete of 实验 A, the one with a password: Escape backs out, then confirm.
  await selectRow(session, "实验 A");
  await until(session, (value) => value.detail === "实验 A", "实验 A to open");
  await session.evaluate(clickText(".connection-details-view footer button", "永久删除"));
  const dialog = await waitFor(() => session.evaluate(`(() => {
    const dialog = document.querySelector('[role="alertdialog"][aria-labelledby="connection-delete-title"]');
    return dialog ? { title: dialog.querySelector('h2').textContent, text: dialog.querySelector('#connection-delete-description').textContent, irreversible: dialog.textContent.includes('删除后无法恢复'), focus: document.activeElement?.textContent ?? null, managerInert: document.querySelector('.connection-manager')?.inert === true } : null;
  })()`), { timeoutMs: 10_000, label: "the delete dialog" }).catch(() => null);
  check("delete shows a plan naming the connection, says it cannot be undone, and holds focus", dialog?.title === "永久删除连接？" && dialog.text.includes("实验 A") && dialog.irreversible && dialog.managerInert, dialog);
  await session.screenshot(path.join(evidence, "connection-delete-dialog.png"));
  await session.send("Input.dispatchKeyEvent", { type: "keyDown", key: "Escape", code: "Escape", windowsVirtualKeyCode: 27 });
  await session.send("Input.dispatchKeyEvent", { type: "keyUp", key: "Escape", code: "Escape", windowsVirtualKeyCode: 27 });
  now = await until(session, (value) => value.notice === "连接删除已取消。", "the cancelled delete");
  check("Escape cancels the plan and keeps the connection", now.notice === "连接删除已取消。" && now.count === 2, now);
  await session.evaluate(clickText(".connection-details-view footer button", "永久删除"));
  await waitFor(() => session.evaluate("document.querySelector('[aria-labelledby=\"connection-delete-title\"]') !== null"), { timeoutMs: 10_000, label: "the delete dialog again" });
  await session.evaluate(clickText('[role="alertdialog"] button', "确认永久删除"));
  now = await until(session, (value) => value.notice === "连接与已保存凭据已永久删除，并完成审计验证。", "the delete");
  check("confirming deletes only that connection and reports the verified result", now.count === 1 && now.rows[0] === "实验 B", now);

  // Import: cancelled, then the earlier export (A exists, B comes back).
  answer(null);
  await session.evaluate("document.querySelector('[data-testid=\"connection-import\"]').click(), true");
  now = await until(session, (value) => value.notice === "连接导入已取消。", "the cancelled import");
  check("cancelling the open dialog imports nothing", now.notice === "连接导入已取消。" && now.count === 1, now.notice);
  answer(exportPath);
  await session.evaluate("document.querySelector('[data-testid=\"connection-import\"]').click(), true");
  now = await until(session, (value) => value.notice?.startsWith("连接导入完成") === true, "the import");
  check("import brings back the deleted one and reports the existing one", now.notice === "连接导入完成：导入 1，跳过已有 1，跳过文件内重复 0。" && now.count === 2, now);

  // Files the import must refuse whole.
  const document = JSON.parse(exported);
  const entries = document.connections;
  const malformed = path.join(files, "malformed.json");
  fs.writeFileSync(malformed, '{"connections": [');
  const oversized = path.join(files, "oversized.json");
  fs.writeFileSync(oversized, `${exported}${" ".repeat(2 * 1024 * 1024)}`);
  const tooMany = path.join(files, "too-many.json");
  fs.writeFileSync(tooMany, JSON.stringify({ ...document, connections: Array.from({ length: 1_001 }, (_, index) => ({ ...entries[0], name: `批量 ${index}`, host: `192.0.2.${(index % 200) + 20}`, port: 1_000 + index })) }));
  const mixed = path.join(files, "one-bad-entry.json");
  fs.writeFileSync(mixed, JSON.stringify({ ...document, connections: [{ ...entries[0], name: "新的正常条目", host: "192.0.2.50" }, { ...entries[0], name: "坏条目", host: "host; touch /tmp/pwned" }] }));
  for (const [label, file] of [["malformed JSON", malformed], ["a file over 2 MiB", oversized], ["more than 1000 entries", tooMany], ["one invalid entry among valid ones", mixed]]) {
    answer(file);
    await session.evaluate("document.querySelector('[data-testid=\"connection-import\"]').click(), true");
    // The click clears the previous message first; let that render before waiting.
    await delay(400);
    now = await until(session, (value) => value.error !== null, `the refused import of ${label}`, 15_000);
    check(`import refuses ${label}, says so plainly and adds nothing`,
      now.error === "这个文件不是有效的连接导出，或超出上限（2 MiB、1000 个连接）。没有导入任何连接。" && now.count === 2,
      { error: now.error, count: now.count });
  }
  await session.screenshot(path.join(evidence, "connection-manager.png"));
});

await run("after restart", async (session) => {
  const now = await until(session, (value) => value.count === 2, "the stored connections", 15_000);
  check("both connections survive a restart", now.count === 2 && now.rows.includes("实验 A") && now.rows.includes("实验 B"), now.rows);
  await selectRow(session, "实验 A");
  const a = await until(session, (value) => value.detail === "实验 A", "实验 A");
  await selectRow(session, "实验 B");
  const b = await until(session, (value) => value.detail === "实验 B", "实验 B");
  // 实验 A was deleted and came back from the export: its password did not travel.
  check("the re-imported connection arrived without its password", a.credential === "缺少密码" && b.credential === "连接时交互输入", { a: a.credential, b: b.credential });
});

// A damaged store must read as an error, not as "no connections": the list
// cannot say there is nothing saved when it could not read what is saved.
const store = path.join(runRoot, "data", "connections.json");
fs.copyFileSync(store, path.join(files, "connections.json.before-damage"));
fs.writeFileSync(store, "{ this is not the store");
await run("damaged store", async (session) => {
  const now = await until(session, (value) => value.error !== null, "the read error", 15_000);
  const listText = await session.evaluate("document.querySelector('.connection-list-empty')?.textContent ?? null");
  const countText = await session.evaluate("document.querySelector('.connection-sidebar-meta strong')?.textContent ?? null");
  check("a store that cannot be read is reported as such, not as an empty list",
    now.error?.startsWith("无法读取本机保存的连接文件") === true && !now.error.includes("(connections-store-unreadable)") &&
      listText === "已保存的连接没有读出来，原因见上方提示。" && countText === "连接未读出",
    { error: now.error, list: listText, count: countText });
  await session.screenshot(path.join(evidence, "connection-store-damaged.png"));
  // The rest of the app stays open: close the manager and look at the landing page.
  await session.evaluate("document.querySelector('[aria-label=\"关闭连接管理\"]').click(), true");
  const landing = await waitFor(() => session.evaluate(`(() => {
    const alert = document.querySelector('[data-testid="welcome-view"] .empty-state[role="alert"]');
    return alert ? { alert: alert.textContent, nav: document.querySelectorAll('.nav-item').length } : null;
  })()`), { timeoutMs: 10_000, label: "the landing page" }).catch(() => null);
  check("the landing page says the saved connections could not be read, and every page is still there", landing?.alert.startsWith("无法读取本机保存的连接文件") === true && landing.nav >= 15, landing);
  await session.evaluate("document.querySelector('[data-testid=\"open-connections\"]').click(), true");
  await waitFor(() => session.evaluate("document.querySelector('.connection-manager') !== null"), { timeoutMs: 10_000, label: "the manager again" });
});
check("the damaged file was left as it was, for the operator to inspect", fs.readFileSync(store, "utf8") === "{ this is not the store");

const failed = checks.filter((entry) => !entry.ok);
fs.writeFileSync(path.join(evidence, "report.json"), `${JSON.stringify({
  schema: "lovelyhawk-connections-probe/v1",
  status: failed.length === 0 ? "PASS" : "FAIL",
  generatedAt: new Date().toISOString(),
  checks,
}, null, 2)}\n`);
console.log(`${failed.length === 0 ? "PASS" : "FAIL"}: ${checks.length - failed.length}/${checks.length}; evidence in ${evidence}`);
process.exitCode = failed.length === 0 ? 0 : 1;
