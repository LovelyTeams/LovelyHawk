// The application log overlay under the Tauri shell: bounded in-memory
// records, display filters, the capture level, copy through the host
// clipboard, export through the host save dialog (cancel, write, refuse to
// overwrite), clearing the buffer, Escape and focus return, the rolling file
// under data/logs that outlives the run — and that a password typed into the
// app reaches neither the overlay nor the file. Throwaway data root; the
// connection below uses a documentation address and is never contacted.
// Dialog answers and the clipboard go through the debug-only hooks.

import { randomUUID } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { attach, delay, launchDesktop, waitFor } from "./cdp.mjs";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const executable = path.join(repositoryRoot, "target", "debug", process.platform === "win32" ? "lovelyhawk.exe" : "lovelyhawk");
const runRoot = path.join(repositoryRoot, "target", "desktop-debug", `application-log-${randomUUID()}`);
const evidence = path.join(runRoot, "evidence");
const files = path.join(runRoot, "files");
const answersFile = path.join(runRoot, "dialog-answers.json");
const clipboardFile = path.join(runRoot, "clipboard.txt");
const exportPath = path.join(files, "application.log");
const logFile = path.join(runRoot, "data", "logs", "lovelyhawk.log");
const secret = `Log-Probe-Secret-${randomUUID()}`;
const checks = [];
function check(name, ok, detail = null) {
  checks.push({ name, ok: Boolean(ok), detail });
  console.log(`${ok ? "PASS" : "FAIL"} ${name}${detail === null ? "" : ` — ${JSON.stringify(detail)}`}`);
}
fs.mkdirSync(evidence, { recursive: true });
fs.mkdirSync(files, { recursive: true });
const answer = (...answers) => fs.writeFileSync(answersFile, JSON.stringify(answers));
answer();

const port = 10_600 + Math.floor(Math.random() * 200);
const { child, output } = launchDesktop({
  executable,
  archiveRoot: runRoot,
  port,
  extraEnv: { LOVELYHAWK_TEST_DIALOG_ANSWERS: answersFile, LOVELYHAWK_TEST_CLIPBOARD_FILE: clipboardFile },
});
let exitCode = null;
child.once("exit", (code) => { exitCode = code; });
const errors = [];

const clickText = (selector, text) => `(() => {
  const element = [...document.querySelectorAll(${JSON.stringify(selector)})].find((candidate) => candidate.textContent.trim() === ${JSON.stringify(text)});
  if (!element || element.disabled) return false;
  element.click();
  return true;
})()`;
const overlay = `(() => {
  const dialog = document.querySelector('[role="dialog"][aria-labelledby="application-log-title"]');
  if (!dialog) return null;
  const counts = dialog.querySelector('.application-log-toolbar > span')?.textContent ?? '';
  return {
    buffered: Number((dialog.querySelector('.application-log-heading span')?.textContent ?? '').match(/(\\d+)\\/500/u)?.[1] ?? -1),
    matched: Number(counts.match(/匹配 (\\d+)/u)?.[1] ?? -1),
    shown: Number(counts.match(/显示 (\\d+)/u)?.[1] ?? -1),
    entries: dialog.querySelectorAll('.application-log-entry').length,
    levels: [...new Set([...dialog.querySelectorAll('.application-log-entry')].map((entry) => entry.className.replace('application-log-entry', '').trim()))],
    plain: [...dialog.querySelectorAll('.application-log-entry pre, .application-log-entry dd')].every((node) => node.children.length === 0),
    notice: dialog.querySelector('.application-log-notice')?.textContent ?? null,
    noticeIsError: dialog.querySelector('.application-log-notice')?.classList.contains('error') ?? false,
    empty: dialog.querySelector('.application-log-state:not([role])')?.textContent ?? null,
    focus: document.activeElement?.getAttribute('placeholder') ?? document.activeElement?.textContent ?? null,
    footnote: dialog.querySelector('.application-log-footnote')?.textContent ?? null,
    text: dialog.textContent,
  };
})()`;
const until = (session, predicate, label, timeoutMs = 10_000) =>
  waitFor(async () => { const value = await session.evaluate(overlay); return value !== null && predicate(value) ? value : null; }, { timeoutMs, label }).catch(async () => session.evaluate(overlay));
const select = (selector, value) => `(() => {
  const element = document.querySelector(${JSON.stringify(selector)});
  Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, 'value').set.call(element, ${JSON.stringify(value)});
  element.dispatchEvent(new Event('change', { bubbles: true }));
  return true;
})()`;

try {
  const { session } = await attach(port, (url) => /^https?:\/\/tauri\.localhost\/(index\.html)?$/u.test(url));
  session.onEvent((method, params) => {
    if (method === "Runtime.exceptionThrown" || (method === "Runtime.consoleAPICalled" && params?.type === "error")) {
      errors.push(JSON.stringify(params).slice(0, 1_500));
    }
  });
  await session.send("Runtime.enable");

  // Put a password through the app first, so the log has had a chance to see it.
  await waitFor(() => session.evaluate("document.querySelector('[data-testid=\"open-connections\"]') !== null"), { label: "the title bar" });
  await session.evaluate("document.querySelector('[data-testid=\"open-connections\"]').click(), true");
  await waitFor(() => session.evaluate("document.querySelector('.connection-manager') !== null && !(document.querySelector('.connection-sidebar-meta span')?.textContent ?? '').includes('读取中')"), { timeoutMs: 15_000, label: "the connection manager" });
  await waitFor(() => session.evaluate(clickText(".connection-manager-header button", "新建连接")), { timeoutMs: 10_000, label: "新建连接 to be available" });
  await waitFor(() => session.evaluate("document.querySelector('.connection-editor') !== null"), { timeoutMs: 10_000, label: "the editor" });
  for (const [label, value] of [["连接名称", "日志探针"], ["主机名或 IP", "192.0.2.30"], ["SSH 密码", secret]]) {
    await session.evaluate(`(() => {
      const input = [...document.querySelectorAll('.connection-editor .connection-field')].find((field) => field.querySelector('span')?.textContent.startsWith(${JSON.stringify(label)}))?.querySelector('input');
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(input, ${JSON.stringify(value)});
      input.dispatchEvent(new Event('input', { bubbles: true }));
      return true;
    })()`);
  }
  await session.evaluate("document.querySelector('.connection-editor button[type=\"submit\"]').click(), true");
  await waitFor(() => session.evaluate("document.querySelector('.connection-notice')?.textContent === '连接已写入便携加密存储。'"), { timeoutMs: 10_000, label: "the saved connection" });
  // A refused save — password authentication with no password — is logged as
  // an error, so the overlay has a real record to show, copy and export.
  await waitFor(() => session.evaluate(clickText(".connection-manager-header button", "新建连接")), { timeoutMs: 10_000, label: "新建连接 again" });
  await waitFor(() => session.evaluate("document.querySelector('.connection-editor') !== null"), { timeoutMs: 10_000, label: "the second editor" });
  for (const [label, value] of [["连接名称", "缺密码"], ["主机名或 IP", "192.0.2.31"]]) {
    await session.evaluate(`(() => {
      const input = [...document.querySelectorAll('.connection-editor .connection-field')].find((field) => field.querySelector('span')?.textContent.startsWith(${JSON.stringify(label)}))?.querySelector('input');
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(input, ${JSON.stringify(value)});
      input.dispatchEvent(new Event('input', { bubbles: true }));
      return true;
    })()`);
  }
  await session.evaluate("document.querySelector('.connection-editor button[type=\"submit\"]').click(), true");
  const refused = await waitFor(() => session.evaluate("document.querySelector('.connection-notice.error')?.textContent ?? null"), { timeoutMs: 10_000, label: "the refused save" }).catch(() => null);
  check("a save without the required password is refused in plain Chinese", typeof refused === "string" && /[一-鿿]/u.test(refused) && !refused.includes("LovelyHawk could not"), refused);
  await session.evaluate(clickText(".connection-editor footer button", "取消"));
  await delay(300);
  // Discarding the unsaved draft asks first.
  await session.evaluate(`[...document.querySelectorAll('[role="dialog"] button, [role="alertdialog"] button')].find((button) => /放弃/u.test(button.textContent))?.click(), true`);
  await delay(300);
  await session.evaluate("document.querySelector('[aria-label=\"关闭连接管理\"]').click(), true");
  await delay(500);

  // Open the log from the status bar, or from the sidebar when it is hidden.
  const opener = await session.evaluate("document.querySelector('[data-testid=\"open-application-log\"]') ? 'open-application-log' : 'sidebar-open-application-log'");
  await session.evaluate(`document.querySelector('[data-testid="${opener}"]').focus(), document.querySelector('[data-testid="${opener}"]').click(), true`);
  let now = await until(session, (value) => value.entries > 0, "log entries", 15_000);
  check("the overlay opens with focus in its filter and shows bounded records", now.focus === "模块、消息或字段" && now.entries > 0 && now.buffered <= 500 && now.shown <= 100 && now.shown === now.entries, { focus: now.focus, buffered: now.buffered, shown: now.shown });
  check("records are plain text", now.plain);
  check("the saved password is not in the log", !now.text.includes(secret));
  check("the overlay says the log is also written to data/logs/lovelyhawk.log", now.footnote?.startsWith("日志同时写入程序旁的 data/logs/lovelyhawk.log") === true, now.footnote);
  const logFileBeforeClear = fs.existsSync(logFile) ? fs.readFileSync(logFile, "utf8") : "";

  await session.evaluate(select(".application-log-toolbar label:nth-of-type(2) select", "error"));
  now = await until(session, (value) => value.entries > 0 && value.levels.every((level) => level === "error"), "the ERROR filter");
  check("the ERROR filter shows the refused save and nothing else", now.entries > 0 && now.levels.every((level) => level === "error"), { levels: now.levels, entries: now.entries });
  await session.evaluate(select(".application-log-toolbar label:nth-of-type(2) select", ""));
  await until(session, (value) => value.entries > 0, "all levels");

  await session.evaluate(select('select[aria-label="当前采集级别"]', "debug"));
  now = await until(session, (value) => value.notice?.startsWith("采集级别已切换为 DEBUG") === true, "the capture level");
  check("the capture level changes for this run and says it is not saved", now.notice === "采集级别已切换为 DEBUG，只对本次运行有效，不会写入设置。", now.notice);
  await session.evaluate(select('select[aria-label="当前采集级别"]', "info"));
  await until(session, (value) => value.notice?.startsWith("采集级别已切换为 INFO") === true, "the capture level back");

  fs.rmSync(clipboardFile, { force: true });
  await session.evaluate(clickText(".application-log-actions button", "复制筛选结果"));
  now = await until(session, (value) => value.notice?.startsWith("已复制") === true, "the copy");
  const copied = fs.existsSync(clipboardFile) ? fs.readFileSync(clipboardFile, "utf8") : "";
  check("copy hands the filtered records to the host clipboard", /^已复制 \d+ 条日志/u.test(now.notice ?? "") && copied.length > 0 && !copied.includes(secret), { notice: now.notice, length: copied.length });

  answer(null);
  await session.evaluate(clickText(".application-log-actions button", "导出 .log"));
  now = await until(session, (value) => value.notice === "已取消日志导出。", "the cancelled export");
  check("cancelling the save dialog writes nothing", now.notice === "已取消日志导出。" && !fs.existsSync(exportPath), now.notice);
  answer(exportPath);
  await session.evaluate(clickText(".application-log-actions button", "导出 .log"));
  now = await until(session, (value) => value.notice?.startsWith("已导出") === true, "the export");
  const exported = fs.existsSync(exportPath) ? fs.readFileSync(exportPath, "utf8") : "";
  check("export writes the records to the chosen file", /^已导出 \d+ 条日志到 application\.log/u.test(now.notice ?? "") && exported.length > 0 && !exported.includes(secret), { notice: now.notice, bytes: exported.length });
  const before = fs.readFileSync(exportPath);
  answer(exportPath);
  await session.evaluate(clickText(".application-log-actions button", "导出 .log"));
  now = await until(session, (value) => value.noticeIsError, "the refused overwrite");
  check("exporting over an existing file is refused and leaves it untouched", now.notice === "日志导出失败。已有同名文件不会被覆盖。" && fs.readFileSync(exportPath).equals(before), now.notice);

  await session.evaluate(clickText(".application-log-actions button", "清空内存缓冲"));
  now = await until(session, (value) => value.notice?.startsWith("已清除") === true, "the clear");
  check("clearing empties the in-memory buffer and says the log file and exported files stay", /^已清除 \d+ 条内存中的日志；日志文件和之前导出的 \.log 文件不受影响。$/u.test(now.notice ?? "") && now.buffered < 10 && fs.existsSync(exportPath), { notice: now.notice, buffered: now.buffered });
  const logFileAfterClear = fs.existsSync(logFile) ? fs.readFileSync(logFile, "utf8") : "";
  check("clearing leaves what the log file already holds", logFileBeforeClear.length > 0 && logFileAfterClear.startsWith(logFileBeforeClear), { before: logFileBeforeClear.length, after: logFileAfterClear.length });
  await session.screenshot(path.join(evidence, "application-log.png"));

  await session.send("Input.dispatchKeyEvent", { type: "keyDown", key: "Escape", code: "Escape", windowsVirtualKeyCode: 27 });
  await session.send("Input.dispatchKeyEvent", { type: "keyUp", key: "Escape", code: "Escape", windowsVirtualKeyCode: 27 });
  const closed = await waitFor(() => session.evaluate(`document.querySelector('[aria-labelledby="application-log-title"]') === null ? (document.activeElement?.dataset.testid ?? '') : null`), { timeoutMs: 5_000, label: "the overlay to close" }).catch(() => null);
  check("Escape closes the overlay and returns focus to the button that opened it", closed === opener, closed);
  check("the page offers no way to read an arbitrary local file", await session.evaluate("Object.keys(window.lovelyhawk).filter((name) => /readFile|openPath|readLocal|fs/i.test(name)).length === 0"));

  check("no console errors", errors.length === 0, errors.slice(0, 3));
  await session.evaluate("document.querySelector('[data-testid=\"window-close\"]').click(), true");
  await waitFor(() => exitCode !== null, { timeoutMs: 15_000, label: "exit" }).catch(() => undefined);
  check("the app exits cleanly", exitCode === 0, exitCode);

  // What is left on disk after the program has gone: whole, timestamped lines
  // with the refused save in them, and never the password.
  const kept = fs.existsSync(logFile) ? fs.readFileSync(logFile, "utf8") : "";
  const lines = kept.split("\n").filter((line) => line.length > 0);
  check("the log file outlives the program and holds whole timestamped lines", lines.length > 0 && kept.endsWith("\n") &&
    lines.every((line) => /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z (DEBUG|INFO|WARN|ERROR) \S+ /u.test(line)), { lines: lines.length, first: lines[0]?.slice(0, 160) ?? null });
  check("the log file records the refused save as an error", lines.some((line) => / ERROR /u.test(line)), lines.filter((line) => / ERROR /u.test(line)).map((line) => line.slice(0, 200)));
  check("the saved password never reaches the log file", kept.length > 0 && !kept.includes(secret));
  check("only the current log file exists for a short run", JSON.stringify(fs.existsSync(path.dirname(logFile)) ? fs.readdirSync(path.dirname(logFile)).sort() : []) === JSON.stringify(["lovelyhawk.log"]),
    fs.existsSync(path.dirname(logFile)) ? fs.readdirSync(path.dirname(logFile)) : null);
} catch (error) {
  check("probe completed", false, error instanceof Error ? error.message : String(error));
  console.error(output.join("").slice(-3_000));
} finally {
  if (exitCode === null) child.kill();
}

const failed = checks.filter((entry) => !entry.ok);
fs.writeFileSync(path.join(evidence, "report.json"), `${JSON.stringify({
  schema: "lovelyhawk-application-log-probe/v1",
  status: failed.length === 0 ? "PASS" : "FAIL",
  generatedAt: new Date().toISOString(),
  checks,
}, null, 2)}\n`);
console.log(`${failed.length === 0 ? "PASS" : "FAIL"}: ${checks.length - failed.length}/${checks.length}; evidence in ${evidence}`);
process.exitCode = failed.length === 0 ? 0 : 1;
