// The disposal report with operations that really ran. In a fresh directory
// under /tmp on a lab host, the terminal window's file manager creates a
// folder whose name is hostile HTML and then deletes it (the delete keeps a
// recoverable copy). The main window's 处置报告 must then count both, show the
// name as text in every preview, copy exactly, export Markdown and HTML as new
// files through the native save dialog (answered by the debug dialog hook),
// refuse to overwrite with the host's reason, write nothing when cancelled,
// return focus on close, and show none of it for another host. The directory
// is removed by its exact path at the end.
//
//   node ui/scripts/probe-disposal-report.mjs

import { execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { labTarget } from "../../tools/lab/lab-target.mjs";
import { Sidecar, backendBinary, connect } from "../../tools/lab/rpc-harness.mjs";
import { attach, delay, launchDesktop, waitFor } from "./cdp.mjs";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const executable = path.join(repositoryRoot, "target", "debug", process.platform === "win32" ? "lovelyhawk.exe" : "lovelyhawk");
const id = randomUUID().slice(0, 8);
const fixtureName = `lh-report-${id}`;
const remoteDirectory = `/tmp/${fixtureName}`;
const hostileName = `<img src=x onerror=alert(${id})>`;
const runRoot = path.join(repositoryRoot, "target", "desktop-debug", `disposal-report-${randomUUID()}`);
const evidence = path.join(runRoot, "evidence");
const files = path.join(runRoot, "files");
const answersFile = path.join(runRoot, "dialog-answers.json");
const clipboardFile = path.join(runRoot, "clipboard.txt");
const checks = [];
function check(name, ok, detail = null) {
  checks.push({ name, ok: Boolean(ok), detail });
  console.log(`${ok ? "PASS" : "FAIL"} ${name}${detail === null ? "" : ` — ${JSON.stringify(detail).slice(0, 400)}`}`);
}
fs.mkdirSync(evidence, { recursive: true });
fs.mkdirSync(files, { recursive: true });
// Every dialog gets a scripted answer; an empty list would show the real one.
const answer = (...answers) => fs.writeFileSync(answersFile, JSON.stringify(answers));
answer(null);
function onHost(script) {
  return execFileSync("wsl.exe", ["-d", "Ubuntu", "-u", "root", "-e", "docker", "exec", "lab-ubuntu", "sh", "-c", script], { encoding: "utf8" });
}
onHost(`mkdir ${remoteDirectory}`);

const hosts = [
  { lab: "ubuntu", name: "实验 ubuntu", id: "11111111-1111-4111-8111-111111111111" },
  { lab: "debian", name: "实验 debian", id: "22222222-2222-4222-8222-222222222222" },
];
const sidecar = new Sidecar(backendBinary(), runRoot);
try {
  for (const host of hosts) {
    const status = await connect(sidecar, { ...labTarget(host.lab), name: host.name, id: host.id });
    if (status?.stage !== "connected") throw new Error(`lab connect failed: ${JSON.stringify(status)}`);
    await sidecar.call("ssh.binding.disconnect", { bindingHandle: status.bindingHandle });
  }
} finally {
  sidecar.close();
}
await delay(500);

const port = 11_700 + Math.floor(Math.random() * 80);
const { child, output } = launchDesktop({ executable, archiveRoot: runRoot, port, extraEnv: { LOVELYHAWK_TEST_DIALOG_ANSWERS: answersFile, LOVELYHAWK_TEST_CLIPBOARD_FILE: clipboardFile } });
let exitCode = null;
child.once("exit", (code) => { exitCode = code; });
const errors = [];
const clickText = (selector, text) => `(() => { const element = [...document.querySelectorAll(${JSON.stringify(selector)})].find((candidate) => candidate.textContent.trim() === ${JSON.stringify(text)}); if (!element || element.disabled) return false; element.click(); return true; })()`;
const row = (name) => `[...document.querySelectorAll('section[aria-label="远程文件"] .sftp-browser-row')].find((candidate) => candidate.querySelector('.sftp-browser-row-label')?.textContent === ${JSON.stringify(name)})`;
const reportState = `(() => {
  const overlay = document.querySelector('.disposal-report-overlay');
  if (!overlay) return null;
  return {
    cards: Object.fromEntries([...overlay.querySelectorAll('.disposal-report-summary-grid article')].map((card) => [card.querySelector('span')?.textContent ?? '', Number(card.querySelector('strong')?.textContent ?? NaN)])),
    empty: overlay.querySelector('.disposal-report-empty-report')?.textContent ?? null,
    loading: overlay.querySelector('.disposal-report-empty[role="status"]') !== null,
    preview: overlay.querySelector('.disposal-report-preview pre')?.textContent ?? null,
    pressed: overlay.querySelector('nav[aria-label="报告预览格式"] button[aria-pressed="true"]')?.textContent ?? null,
    images: overlay.querySelectorAll('img').length,
    notice: overlay.querySelector('.disposal-report-notice[role="status"]')?.textContent ?? null,
    text: overlay.textContent,
  };
})()`;
try {
  const { session: main } = await attach(port, (url) => /^https?:\/\/tauri\.localhost\/(index\.html)?$/u.test(url));
  main.onEvent((method, params) => {
    if (method === "Runtime.exceptionThrown" || (method === "Runtime.consoleAPICalled" && params?.type === "error")) errors.push(JSON.stringify(params).slice(0, 1_500));
  });
  await main.send("Runtime.enable");
  const until = (predicate, label, timeoutMs = 30_000) => waitFor(async () => {
    const value = await main.evaluate(reportState);
    return value !== null && !value.loading && predicate(value) ? value : null;
  }, { timeoutMs, label });
  async function connectTo(name) {
    await waitFor(() => main.evaluate("(() => { const button = document.querySelector('[data-testid=\"sidebar-connect-target\"]'); if (!button) return false; button.click(); return true; })()"), { label: "连接管理" });
    await waitFor(() => main.evaluate(`(() => { const candidate = [...document.querySelectorAll('.connection-list .connection-list-row')].find((entry) => entry.querySelector('strong')?.textContent === ${JSON.stringify(name)}); if (!candidate || candidate.disabled) return false; candidate.click(); return true; })()`), { timeoutMs: 15_000, label: `the ${name} row` });
    await waitFor(() => main.evaluate(`(() => { const button = [...document.querySelectorAll('.connection-detail button')].find((candidate) => candidate.textContent.trim() === '连接目标' && !candidate.disabled); if (!button) return false; button.click(); return true; })()`), { timeoutMs: 15_000, label: "连接目标" });
    await waitFor(() => main.evaluate("document.querySelector('[data-testid=\"sidebar-disconnect-target\"]') !== null && document.querySelector('.connection-manager-backdrop') === null"), { timeoutMs: 90_000, label: `the connection to ${name}` });
  }
  async function disconnect() {
    await main.evaluate("document.querySelector('[data-testid=\"sidebar-disconnect-target\"]').click(), true");
    await waitFor(() => main.evaluate("document.querySelector('[data-testid=\"sidebar-disconnect-target\"]') === null"), { timeoutMs: 20_000, label: "the disconnect" });
  }
  const openReport = async () => {
    await main.evaluate("document.querySelector('[data-testid=\"open-disposal-report\"]').click(), true");
    return until((value) => Object.hasOwn(value.cards, "处置操作") || value.text.includes("报告生成失败"), "the report");
  };
  const preview = async (label) => {
    await main.evaluate(clickText('nav[aria-label="报告预览格式"] button', label));
    return until((value) => value.pressed === label && value.preview !== null, `the ${label} preview`).catch(async (error) => {
      console.error(JSON.stringify(await main.evaluate(reportState)).slice(0, 1_500));
      throw error;
    });
  };

  await waitFor(() => main.evaluate("document.querySelector('[data-testid=\"sidebar-connect-target\"]') !== null"), { label: "the sidebar" });
  await connectTo("实验 ubuntu");
  let state = await openReport();
  check("a host with nothing done yet gets an empty report that says so", state.empty?.includes("还没有记录在案的处置操作") === true && state.cards["处置操作"] === 0, { empty: state.empty, cards: state.cards });
  await main.evaluate("document.querySelector('[data-testid=\"close-disposal-report\"]').click(), true");
  await waitFor(() => main.evaluate("document.querySelector('.disposal-report-overlay') === null"), { label: "the report to close" });

  // Two real operations in the terminal window's file manager.
  await main.evaluate("document.querySelector('[data-testid=\"sidebar-open-terminal\"]').click(), true");
  const { session: terminal } = await attach(port, (url) => url.includes("/terminal.html?window=terminal"), 30_000);
  await terminal.send("Runtime.enable");
  for (const name of ["tmp", fixtureName]) {
    await waitFor(() => terminal.evaluate(`(() => { const candidate = ${row(name)}; if (!candidate || candidate.disabled) return false; candidate.dispatchEvent(new MouseEvent('dblclick', { bubbles: true })); return true; })()`), { timeoutMs: 30_000, label: `the ${name} directory` });
    await delay(800);
  }
  await waitFor(() => terminal.evaluate(`document.querySelector('section[aria-label="远程文件"] .sftp-browser-path-value')?.textContent?.includes(${JSON.stringify(fixtureName)}) === true`), { timeoutMs: 20_000, label: "the fixture directory" }).catch(async (error) => {
    console.error(await terminal.evaluate("JSON.stringify({ path: document.querySelector('.sftp-browser-path-value')?.textContent ?? null, rows: [...document.querySelectorAll('section[aria-label=\"远程文件\"] .sftp-browser-row-label')].map((label) => label.textContent).slice(0, 30), status: document.querySelector('.sftp-browser-status, .sftp-browser-error')?.textContent ?? null })"));
    throw error;
  });
  async function runOperation(start, prepare = null) {
    await terminal.evaluate(start);
    await waitFor(() => terminal.evaluate("document.querySelector('[data-testid=\"sftp-operation-dialog\"]') !== null"), { label: "the operation dialog" });
    if (prepare !== null) await terminal.evaluate(prepare);
    await waitFor(() => terminal.evaluate(clickText('[data-testid="sftp-operation-dialog"] button', "生成计划")), { label: "生成计划" });
    await waitFor(() => terminal.evaluate("document.querySelector('[data-testid=\"sftp-operation-execute\"]')?.disabled === false"), { timeoutMs: 30_000, label: "the plan" });
    const label = await terminal.evaluate("document.querySelector('[data-testid=\"sftp-operation-execute\"]').textContent");
    await terminal.evaluate("document.querySelector('[data-testid=\"sftp-operation-execute\"]').click(), true");
    const receipt = await waitFor(() => terminal.evaluate("document.querySelector('.sftp-operation-receipt')?.textContent ?? null"), { timeoutMs: 60_000, label: "the receipt" });
    await terminal.evaluate(clickText('[data-testid="sftp-operation-dialog"] footer button', "关闭"));
    await delay(600);
    return { receipt, dangerous: label === "确认并执行" };
  }
  const setName = `(() => { const input = document.querySelector('[data-testid="sftp-operation-dialog"] input'); Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(input, ${JSON.stringify(hostileName)}); input.dispatchEvent(new Event('input', { bubbles: true })); return true; })()`;
  const created = await runOperation(clickText(".sftp-browser-actions button", "新建文件夹"), setName);
  check("the folder was created and checked", created.receipt?.startsWith("已完成并通过校验") === true, created.receipt);
  await waitFor(() => terminal.evaluate(`${row(hostileName)} !== undefined`), { timeoutMs: 20_000, label: "the new folder in the list" });
  await terminal.evaluate(`${row(hostileName)}.click(), true`);
  const removed = await runOperation(clickText(".sftp-browser-actions button", "删除"));
  check("the folder was deleted with a recoverable copy", removed.receipt?.startsWith("已完成并通过校验") === true && removed.dangerous, removed);
  const onDisk = onHost(`ls -A ${remoteDirectory}`).trim();
  check("on the host the folder is gone and the copy is kept beside it", onDisk === ".lovelyres-backups", onDisk);

  // The report.
  state = await openReport();
  state = await until((value) => value.cards["处置操作"] === 2, "a report with two operations");
  check("the report counts both operations as succeeded and recoverable where they are", state.cards["成功"] === 2 && state.cards["失败"] === 0 && state.empty === null, state.cards);
  const summary = await preview("摘要纯文本");
  const markdown = await preview("Markdown 纯文本");
  const html = await preview("HTML 源码纯文本");
  const escapedName = hostileName.replaceAll("<", "&lt;").replaceAll(">", "&gt;");
  check("every preview shows the hostile name only as text, escaped in Markdown and HTML", markdown.preview.includes(escapedName) && !markdown.preview.includes(hostileName) && summary.images === 0 && markdown.images === 0 && html.images === 0, { markdownEscaped: markdown.preview.includes(escapedName), images: [summary.images, markdown.images, html.images] });
  const banned = /不可变|快照 SHA|审计操作|检测项：|代际|目标身份/u;
  check("the report itself uses no internal terms", [summary.preview, markdown.preview, html.preview].every((text) => !banned.test(text)), [summary.preview, markdown.preview, html.preview].map((text) => text.match(banned)?.[0] ?? null));
  check("the HTML source escapes the name", html.preview.includes("&lt;img src=x onerror=alert(") && !html.preview.includes(hostileName), html.preview.slice(0, 120));
  await main.screenshot(path.join(evidence, "disposal-report.png"));

  fs.rmSync(clipboardFile, { force: true });
  await main.evaluate(clickText(".disposal-report-heading button", "复制当前纯文本"));
  state = await until((value) => value.notice?.includes("已复制") === true, "the copy notice");
  const copied = fs.existsSync(clipboardFile) ? fs.readFileSync(clipboardFile, "utf8") : null;
  check("copying hands over exactly the HTML source shown", copied === html.preview, { notice: state.notice, length: copied?.length });

  const markdownFile = path.join(files, "report.md");
  await preview("Markdown 纯文本");
  answer(markdownFile);
  await main.evaluate(clickText(".disposal-report-heading button", "保存 MD"));
  state = await until((value) => value.notice?.startsWith("已导出") === true, "the Markdown export");
  const writtenMarkdown = fs.existsSync(markdownFile) ? fs.readFileSync(markdownFile, "utf8") : null;
  check("Markdown is saved as a new file with exactly the previewed text", state.notice === "已导出 2 项处置操作到 report.md。" && writtenMarkdown === markdown.preview, { notice: state.notice, same: writtenMarkdown === markdown.preview });

  answer(markdownFile);
  await main.evaluate(clickText(".disposal-report-heading button", "保存 MD"));
  state = await until((value) => value.notice?.startsWith("处置报告没有导出") === true, "the refused overwrite");
  check("saving over an existing file is refused with the reason, and the file is untouched", state.notice.includes("所选文件已存在") && fs.readFileSync(markdownFile, "utf8") === writtenMarkdown, state.notice);

  answer(null);
  await main.evaluate(clickText(".disposal-report-heading button", "保存 HTML"));
  state = await until((value) => value.notice === "已取消导出，没有写入文件。", "the cancelled export");
  check("a cancelled export writes nothing", fs.readdirSync(files).join(",") === "report.md", fs.readdirSync(files));

  const htmlFile = path.join(files, "report.html");
  answer(htmlFile);
  await main.evaluate(clickText(".disposal-report-heading button", "保存 HTML"));
  state = await until((value) => value.notice === "已导出 2 项处置操作到 report.html。", "the HTML export");
  const writtenHtml = fs.existsSync(htmlFile) ? fs.readFileSync(htmlFile, "utf8") : "";
  check("the saved HTML is the previewed source with the name escaped", writtenHtml === html.preview && !writtenHtml.includes(hostileName), { length: writtenHtml.length });

  await main.evaluate("document.querySelector('[data-testid=\"close-disposal-report\"]').click(), true");
  await waitFor(() => main.evaluate("document.querySelector('.disposal-report-overlay') === null"), { label: "the report to close" });
  const focusBack = await main.evaluate("document.activeElement?.getAttribute('data-testid') ?? null");
  check("closing returns focus to the button that opened it", focusBack === "open-disposal-report", focusBack);

  await disconnect();
  await connectTo("实验 debian");
  state = await openReport();
  check("another host's report includes none of it", state.cards["处置操作"] === 0 && !state.text.includes(fixtureName), state.cards);
  await main.evaluate("document.querySelector('[data-testid=\"close-disposal-report\"]').click(), true");
  await delay(300);

  const visibleText = await main.evaluate("document.body.innerText");
  check("the overlay's own wording has no internal terms", !banned.test(visibleText + state.text), (visibleText + state.text).match(banned)?.[0] ?? null);
  check("no console errors in the main window", errors.length === 0, errors.slice(0, 3));
  await disconnect();
  await main.evaluate("document.querySelector('[data-testid=\"window-close\"]').click(), true");
  await waitFor(() => exitCode !== null, { timeoutMs: 15_000, label: "exit" }).catch(() => undefined);
  check("the app exits cleanly", exitCode === 0, exitCode);
} catch (error) {
  check("probe completed", false, error instanceof Error ? error.message : String(error));
  console.error(output.join("").slice(-3_000));
} finally {
  if (exitCode === null) child.kill();
  onHost(`rm -rf ${remoteDirectory}`);
  check("the lab directory was removed", onHost(`test -e ${remoteDirectory} && echo present || echo gone`).trim() === "gone");
}

const failed = checks.filter((entry) => !entry.ok);
fs.writeFileSync(path.join(evidence, "report.json"), `${JSON.stringify({
  schema: "lovelyhawk-disposal-report-probe/v1",
  status: failed.length === 0 ? "PASS" : "FAIL",
  generatedAt: new Date().toISOString(),
  checks,
}, null, 2)}\n`);
console.log(`${failed.length === 0 ? "PASS" : "FAIL"}: ${checks.length - failed.length}/${checks.length}; evidence in ${evidence}`);
process.exitCode = failed.length === 0 ? 0 : 1;
