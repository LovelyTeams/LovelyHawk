// The command history overlay with records that real runs produced. Two
// built-in emergency commands run on one lab host, then the overlay is checked
// the way an operator uses it: the records are there with their titles and a
// plain-language source, a catalog run says what it keeps instead of showing a
// stand-in as a command, the result summary copies exactly, search narrows,
// delete asks first and Escape backs out, a confirmed delete removes exactly
// one record, another host's history never shows, a record opens its check
// again in the workbench (selected, waiting for the operator), a host with more
// runs than one page pages through all of them, and clearing empties it.
// Nothing on the lab hosts is changed: the commands are read-only.
//
//   node ui/scripts/probe-command-history.mjs

import { randomUUID } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { labTarget } from "../../tools/lab/lab-target.mjs";
import { Sidecar, backendBinary, connect } from "../../tools/lab/rpc-harness.mjs";
import { attach, delay, launchDesktop, waitFor } from "./cdp.mjs";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const executable = path.join(repositoryRoot, "target", "debug", process.platform === "win32" ? "lovelyhawk.exe" : "lovelyhawk");
const runRoot = path.join(repositoryRoot, "target", "desktop-debug", `command-history-${randomUUID()}`);
const evidence = path.join(runRoot, "evidence");
const clipboardFile = path.join(runRoot, "clipboard.txt");
const checks = [];
function check(name, ok, detail = null) {
  checks.push({ name, ok: Boolean(ok), detail });
  console.log(`${ok ? "PASS" : "FAIL"} ${name}${detail === null ? "" : ` — ${JSON.stringify(detail).slice(0, 400)}`}`);
}
fs.mkdirSync(evidence, { recursive: true });

// Three saved connections with their host keys accepted. The third gets more
// real runs than one page holds, made through the same backend before the
// window opens, so paging is checked against records that actually exist.
const hosts = [
  { lab: "ubuntu", name: "实验 ubuntu", id: "11111111-1111-4111-8111-111111111111" },
  { lab: "debian", name: "实验 debian", id: "22222222-2222-4222-8222-222222222222" },
  { lab: "rocky", name: "实验 rocky", id: "33333333-3333-4333-8333-333333333333" },
];
const PAGED_RUNS = 26;
let pagedTitles = [];
const sidecar = new Sidecar(backendBinary(), runRoot);
try {
  for (const host of hosts) {
    const status = await connect(sidecar, { ...labTarget(host.lab), name: host.name, id: host.id });
    if (status?.stage !== "connected") throw new Error(`lab connect failed: ${JSON.stringify(status)}`);
    if (host.lab === "rocky") {
      const catalog = await sidecar.call("emergency-command.catalog.load", { bindingHandle: status.bindingHandle }, 120_000);
      const quick = catalog.commands.filter((command) => command.timeoutSeconds <= 30).slice(0, PAGED_RUNS);
      for (const command of quick) {
        await sidecar.call("emergency-command.run", {
          bindingHandle: status.bindingHandle, snapshotHandle: catalog.snapshotHandle, commandHandle: command.commandHandle,
        }, 120_000);
      }
      pagedTitles = quick.map((command) => command.title);
    }
    await sidecar.call("ssh.binding.disconnect", { bindingHandle: status.bindingHandle });
  }
} finally {
  sidecar.close();
}
await delay(500);

const port = 11_600 + Math.floor(Math.random() * 80);
const { child, output } = launchDesktop({ executable, archiveRoot: runRoot, port, extraEnv: { LOVELYHAWK_TEST_CLIPBOARD_FILE: clipboardFile } });
let exitCode = null;
child.once("exit", (code) => { exitCode = code; });
const errors = [];
const clickText = (selector, text) => `(() => { const element = [...document.querySelectorAll(${JSON.stringify(selector)})].find((candidate) => candidate.textContent.trim() === ${JSON.stringify(text)}); if (!element || element.disabled) return false; element.click(); return true; })()`;
const setInput = (selector, value) => `(() => { const input = document.querySelector(${JSON.stringify(selector)}); if (!input) return false; Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(input, ${JSON.stringify(value)}); input.dispatchEvent(new Event('input', { bubbles: true })); return true; })()`;
const panelState = `(() => {
  const panel = document.querySelector('.command-history-panel');
  if (!panel) return null;
  const detail = panel.querySelector('.command-history-detail');
  return {
    total: panel.querySelector('.command-history-list-panel footer span')?.textContent ?? null,
    rows: [...panel.querySelectorAll('.command-history-row')].map((row) => ({
      title: row.querySelector('strong')?.textContent ?? '',
      meta: row.querySelector('small')?.textContent ?? '',
      code: row.querySelector('code')?.textContent ?? null,
      text: row.textContent,
    })),
    empty: [...panel.querySelectorAll('.command-history-list > p')].map((node) => node.textContent).find((text) => text !== '正在读取命令历史…') ?? null,
    detail: detail?.textContent ?? '',
    buttons: [...(detail?.querySelectorAll('header button') ?? [])].map((button) => button.textContent.trim()),
    notice: panel.querySelector('.command-history-notice')?.textContent ?? null,
    text: panel.textContent,
  };
})()`;
try {
  const { session: main } = await attach(port, (url) => /^https?:\/\/tauri\.localhost\/(index\.html)?$/u.test(url));
  main.onEvent((method, params) => {
    if (method === "Runtime.exceptionThrown" || (method === "Runtime.consoleAPICalled" && params?.type === "error")) errors.push(JSON.stringify(params).slice(0, 1_500));
  });
  await main.send("Runtime.enable");
  const until = (predicate, label, timeoutMs = 20_000) => waitFor(async () => {
    const value = await main.evaluate(panelState);
    return value !== null && predicate(value) ? value : null;
  }, { timeoutMs, label });
  const key = async (name, code, windowsVirtualKeyCode) => {
    await main.send("Input.dispatchKeyEvent", { type: "keyDown", key: name, code, windowsVirtualKeyCode });
    await main.send("Input.dispatchKeyEvent", { type: "keyUp", key: name, code, windowsVirtualKeyCode });
  };
  async function connectTo(name) {
    await waitFor(() => main.evaluate("(() => { const button = document.querySelector('[data-testid=\"sidebar-connect-target\"]'); if (!button) return false; button.click(); return true; })()"), { label: "连接管理" });
    await waitFor(() => main.evaluate(`(() => { const row = [...document.querySelectorAll('.connection-list .connection-list-row')].find((candidate) => candidate.querySelector('strong')?.textContent === ${JSON.stringify(name)}); if (!row || row.disabled) return false; row.click(); return true; })()`), { timeoutMs: 15_000, label: `the ${name} row` });
    await waitFor(() => main.evaluate(`(() => { const button = [...document.querySelectorAll('.connection-detail button')].find((candidate) => candidate.textContent.trim() === '连接目标' && !candidate.disabled); if (!button) return false; button.click(); return true; })()`), { timeoutMs: 15_000, label: "连接目标" });
    await waitFor(() => main.evaluate("document.querySelector('[data-testid=\"sidebar-disconnect-target\"]') !== null && document.querySelector('.connection-manager-backdrop') === null"), { timeoutMs: 90_000, label: `the connection to ${name}` });
  }
  async function disconnect() {
    await main.evaluate("document.querySelector('[data-testid=\"sidebar-disconnect-target\"]').click(), true");
    await waitFor(() => main.evaluate("document.querySelector('[data-testid=\"sidebar-disconnect-target\"]') === null"), { timeoutMs: 20_000, label: "the disconnect" });
  }
  async function openHistory() {
    await main.evaluate("document.querySelector('[data-testid=\"open-command-history\"]').click(), true");
    return until(() => true, "the command history panel");
  }
  async function closeHistory() {
    await main.evaluate(clickText(".command-history-header-actions button", "关闭"));
    await waitFor(() => main.evaluate("document.querySelector('.command-history-panel') === null"), { label: "the panel to close" });
  }
  async function runCommand(title) {
    await waitFor(() => main.evaluate(`(() => { const button = [...document.querySelectorAll('.emergency-commands-list button')].find((candidate) => candidate.textContent.includes(${JSON.stringify(title)})); if (!button || button.disabled) return false; button.click(); return true; })()`), { timeoutMs: 120_000, label: title });
    await waitFor(() => main.evaluate(`document.querySelector('.emergency-command-detail h2')?.textContent === ${JSON.stringify(title)}`), { label: `${title} selected` });
    await waitFor(() => main.evaluate("(() => { const button = document.querySelector('.emergency-command-run'); if (!button || button.disabled) return false; button.click(); return true; })()"), { label: "运行只读调查" });
    await waitFor(() => main.evaluate("document.querySelector('.emergency-command-run')?.textContent.includes('执行中') === false && (document.querySelector('.emergency-command-output') !== null || document.querySelector('.emergency-command-detail [role=\"alert\"]') !== null)"), { timeoutMs: 180_000, label: `${title} output` });
  }

  await waitFor(() => main.evaluate("document.querySelector('[data-testid=\"sidebar-connect-target\"]') !== null"), { label: "the sidebar" });
  await connectTo("实验 ubuntu");
  let state = await openHistory();
  state = await until((value) => value.empty !== null || value.rows.length > 0, "the first list");
  check("a host with no runs yet says its history is empty", state.empty === "当前目标暂无命令历史" && state.rows.length === 0, { empty: state.empty, rows: state.rows.length });
  await closeHistory();

  await main.evaluate(`(() => { const button = [...document.querySelectorAll('.nav-item')].find((candidate) => candidate.textContent?.includes('命令工作台')); button?.click(); return true; })()`);
  await runCommand("监听端口");
  await runCommand("SUID 可执行");

  state = await openHistory();
  state = await until((value) => value.rows.length === 2, "two records");
  const titles = state.rows.map((row) => row.title).sort();
  check("both runs are listed with their titles", JSON.stringify(titles) === JSON.stringify(["SUID 可执行", "监听端口"].sort()) && state.total === "2 条", { titles, total: state.total });
  check("each row names its source in words and shows no stand-in command", state.rows.every((row) => row.meta.includes("应急命令") && row.code === null && !/lovelyres|native-command|workbench/iu.test(row.text)), state.rows.map((row) => row.meta));

  await main.evaluate(`(() => { const row = [...document.querySelectorAll('.command-history-row')].find((candidate) => candidate.querySelector('strong')?.textContent === '监听端口'); row.click(); return true; })()`);
  state = await until((value) => value.detail.includes("结果摘要"), "the record detail");
  check("a catalog run explains what history keeps and offers only what works",
    state.detail.includes("不保存命令全文和原始输出") && state.detail.includes("结果：") &&
    JSON.stringify(state.buttons) === JSON.stringify(["到命令工作台再次运行", "复制结果摘要", "永久删除"]) &&
    !/重放|lovelyres|network-listen/iu.test(state.detail),
    { buttons: state.buttons, detail: state.detail.slice(0, 200) });
  const summaryText = await main.evaluate("document.querySelector('.command-history-detail article pre')?.textContent ?? ''");
  check("the result summary is plain Chinese", summaryText.startsWith("结果：") && !/[A-Za-z]{4,}/u.test(summaryText), summaryText);
  fs.rmSync(clipboardFile, { force: true });
  await main.evaluate(clickText(".command-history-detail header button", "复制结果摘要"));
  await until((value) => value.notice === "已复制结果摘要。", "the copy notice");
  const copied = fs.existsSync(clipboardFile) ? fs.readFileSync(clipboardFile, "utf8") : null;
  check("copying hands over exactly the summary", copied === summaryText, { copied: copied?.slice(0, 80) });
  await main.screenshot(path.join(evidence, "command-history-detail.png"));

  await main.evaluate(setInput('input[aria-label="搜索命令历史"]', "SUID"));
  state = await until((value) => value.rows.length === 1, "the search result");
  check("search narrows the list", state.rows[0]?.title === "SUID 可执行", state.rows.map((row) => row.title));
  await main.evaluate(setInput('input[aria-label="搜索命令历史"]', "没有这个词"));
  state = await until((value) => value.empty !== null, "the empty search");
  check("a search with no match says so", state.empty === "没有匹配的命令历史", state.empty);
  await main.evaluate(setInput('input[aria-label="搜索命令历史"]', ""));
  await until((value) => value.rows.length === 2, "the full list again");

  await main.evaluate(`(() => { const row = [...document.querySelectorAll('.command-history-row')].find((candidate) => candidate.querySelector('strong')?.textContent === '监听端口'); row.click(); return true; })()`);
  await until((value) => value.buttons.includes("永久删除"), "the record detail again");
  await main.evaluate(clickText(".command-history-detail header button", "永久删除"));
  const confirm = await waitFor(() => main.evaluate(`(() => {
    const dialog = document.querySelector('.command-history-confirm[role="alertdialog"]');
    return dialog ? { title: dialog.querySelector('h2')?.textContent ?? '', text: dialog.textContent, focus: document.activeElement?.textContent ?? null, shellInert: document.querySelector('.command-history-shell')?.inert === true } : null;
  })()`), { label: "the delete confirmation" });
  check("delete asks first, with focus on 取消 and the list behind it inert", confirm.title === "永久删除这条命令历史？" && confirm.focus === "取消" && confirm.shellInert && confirm.text.includes("这条记录会被永久删除，无法恢复。") && !/不可变|计划|绑定/u.test(confirm.text), confirm);
  await main.screenshot(path.join(evidence, "command-history-delete.png"));
  await key("Escape", "Escape", 27);
  state = await until((value) => value.notice === "已取消，命令历史没有改动。", "the cancelled delete");
  check("Escape backs out and keeps both records", state.rows.length === 2, { notice: state.notice, rows: state.rows.length });

  await main.evaluate(clickText(".command-history-detail header button", "永久删除"));
  await waitFor(() => main.evaluate(clickText(".command-history-confirm button", "确认永久删除")), { label: "确认永久删除" });
  state = await until((value) => value.notice?.startsWith("已永久删除") === true && value.rows.length === 1, "the delete");
  check("a confirmed delete removes exactly that record and says it was checked", state.notice === "已永久删除 1 条命令历史，并核对了保存结果。" && state.rows[0]?.title === "SUID 可执行", { notice: state.notice, rows: state.rows.map((row) => row.title) });
  await closeHistory();

  await disconnect();
  state = await openHistory();
  check("without a target the panel asks for one", state.text.includes("请先在连接管理中连接 SSH 目标"), state.text.slice(0, 120));
  await closeHistory();
  await connectTo("实验 debian");
  state = await openHistory();
  state = await until((value) => value.empty !== null || value.rows.length > 0, "the other host's list");
  check("another host never shows this host's history", state.rows.length === 0 && state.empty === "当前目标暂无命令历史", { rows: state.rows.map((row) => row.title) });
  await closeHistory();
  await disconnect();

  await connectTo("实验 ubuntu");
  state = await openHistory();
  state = await until((value) => value.rows.length > 0 || value.empty !== null, "the list after reconnecting");
  check("the remaining record is still there after reconnecting", state.rows.length === 1 && state.rows[0].title === "SUID 可执行", state.rows.map((row) => row.title));

  // Run it again from history: the workbench finds the same check, selects
  // it, and waits for the operator.
  await main.evaluate(`(() => { const row = [...document.querySelectorAll('.command-history-row')].find((candidate) => candidate.querySelector('strong')?.textContent === 'SUID 可执行'); row.click(); return true; })()`);
  await until((value) => value.buttons.includes("到命令工作台再次运行"), "the rerun button").catch(async (error) => {
    console.log(JSON.stringify(await main.evaluate(panelState)).slice(0, 1_500));
    throw error;
  });
  await main.evaluate("document.querySelector('[data-testid=\"command-history-rerun\"]').click(), true");
  const revealed = await waitFor(() => main.evaluate(`(() => {
    if (document.querySelector('.command-history-panel') !== null) return null;
    const notice = document.querySelector('[data-testid="emergency-commands-rerun"]');
    if (!notice) return null;
    return {
      notice: notice.textContent,
      title: document.querySelector('.emergency-command-detail h2')?.textContent ?? null,
      focus: document.activeElement?.classList.contains('emergency-command-run') === true,
      output: document.querySelector('.emergency-command-output') !== null,
    };
  })()`), { timeoutMs: 60_000, label: "the workbench with the check from history" });
  check("from history, the workbench selects the same check and waits with focus on 运行只读调查",
    revealed.title === "SUID 可执行" && revealed.focus && !revealed.output && revealed.notice.includes("已从命令历史找到这项检查"), revealed);
  await main.screenshot(path.join(evidence, "command-history-rerun.png"));
  await main.evaluate("document.querySelector('.emergency-command-run').click(), true");
  await waitFor(() => main.evaluate("document.querySelector('.emergency-command-run')?.textContent.includes('执行中') === false && document.querySelector('.emergency-command-output') !== null"), { timeoutMs: 180_000, label: "the rerun output" });
  state = await openHistory();
  state = await until((value) => value.rows.length === 2, "two runs of the same check");
  check("history now holds both runs of that check", state.rows.every((row) => row.title === "SUID 可执行"), state.rows.map((row) => row.title));

  await main.evaluate(clickText(".command-history-header-actions button", "清空目标历史"));
  const clearDialog = await waitFor(() => main.evaluate("document.querySelector('.command-history-confirm h2')?.textContent ?? null"), { label: "the clear confirmation" });
  await waitFor(() => main.evaluate(clickText(".command-history-confirm button", "确认永久删除")), { label: "确认永久删除 (clear)" });
  state = await until((value) => value.empty === "当前目标暂无命令历史", "the cleared list");
  check("clearing asks first and empties this host's history", clearDialog === "永久清空目标命令历史？" && state.notice === "已永久删除 2 条命令历史，并核对了保存结果。", { clearDialog, notice: state.notice });
  await closeHistory();
  const focusBack = await main.evaluate("document.activeElement?.getAttribute('data-testid') ?? null");
  check("closing returns focus to the 命令历史 button", focusBack === "open-command-history", focusBack);
  await disconnect();

  // More records than one page holds, all from real runs on this host.
  await connectTo("实验 rocky");
  state = await openHistory();
  state = await until((value) => value.rows.length > 0, "the first page");
  const firstPage = state.rows.map((row) => row.title);
  const pageButtons = () => main.evaluate(`(() => Object.fromEntries([...document.querySelectorAll('.command-history-list-panel footer button')].map((button) => [button.textContent.trim(), !button.disabled])))()`);
  const firstButtons = await pageButtons();
  check(`${PAGED_RUNS} real runs fill one page of 25, with 下一页 offered and 上一页 not`,
    pagedTitles.length === PAGED_RUNS && state.total === `${PAGED_RUNS} 条` && firstPage.length === 25 && firstButtons["下一页"] === true && firstButtons["上一页"] === false,
    { total: state.total, rows: firstPage.length, buttons: firstButtons, ran: pagedTitles.length });
  await main.evaluate(clickText(".command-history-list-panel footer button", "下一页"));
  state = await until((value) => value.rows.length === PAGED_RUNS - 25, "the second page");
  const secondButtons = await pageButtons();
  check("the second page holds the rest, with 上一页 back and no 下一页",
    secondButtons["上一页"] === true && secondButtons["下一页"] === false &&
      [...firstPage, ...state.rows.map((row) => row.title)].sort().join("|") === [...pagedTitles].sort().join("|"),
    { second: state.rows.map((row) => row.title), buttons: secondButtons });
  await main.screenshot(path.join(evidence, "command-history-page-two.png"));
  await main.evaluate(clickText(".command-history-list-panel footer button", "上一页"));
  state = await until((value) => value.rows.length === 25, "back on the first page");
  check("上一页 returns to the same first page", JSON.stringify(state.rows.map((row) => row.title)) === JSON.stringify(firstPage));
  await closeHistory();

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
}

const failed = checks.filter((entry) => !entry.ok);
fs.writeFileSync(path.join(evidence, "report.json"), `${JSON.stringify({
  schema: "lovelyhawk-command-history-probe/v1",
  status: failed.length === 0 ? "PASS" : "FAIL",
  generatedAt: new Date().toISOString(),
  checks,
}, null, 2)}\n`);
console.log(`${failed.length === 0 ? "PASS" : "FAIL"}: ${checks.length - failed.length}/${checks.length}; evidence in ${evidence}`);
process.exitCode = failed.length === 0 ? 0 : 1;
