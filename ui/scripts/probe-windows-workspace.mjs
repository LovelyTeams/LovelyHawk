// Real WebView2 window, production origin and styles. The disconnected view
// uses the real bridge; connected interaction cases use explicitly synthetic
// snapshots. This probe is not evidence of a live RDP/target round trip.
import { randomUUID } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "vite";
import react from "@vitejs/plugin-react";
import { attach, delay, launchDesktop, waitFor } from "./cdp.mjs";

const ui = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const repository = path.dirname(ui);
const runRoot = path.join(repository, "target", "desktop-debug", `windows-workspace-${randomUUID()}`);
const evidence = path.join(runRoot, "evidence");
fs.mkdirSync(evidence, { recursive: true });
await build({
  root: ui, configFile: false, plugins: [react()], logLevel: "warn",
  define: { "process.env.NODE_ENV": JSON.stringify("production") },
  build: {
    outDir: path.join(runRoot, "fixture"), emptyOutDir: false,
    lib: { entry: path.join(ui, "scripts", "win-ir-workspace-fixture.tsx"), name: "WinIrFixture", formats: ["iife"], fileName: () => "fixture.js" },
  },
});
const checks = [];
const errors = [];
function check(name, ok, detail = null) {
  checks.push({ name, ok: Boolean(ok), detail });
  console.log(`${ok ? "PASS" : "FAIL"} ${name}${detail === null ? "" : ` — ${JSON.stringify(detail)}`}`);
}
const port = 11600 + Math.floor(Math.random() * 100);
const { child, output } = launchDesktop({
  executable: process.env.LOVELYHAWK_DESKTOP_BIN ?? path.join(repository, "target", "debug", "lovelyhawk.exe"), archiveRoot: runRoot, port,
  extraEnv: { LOVELYHAWK_TEST_CLIPBOARD_FILE: path.join(runRoot, "clipboard.txt") },
});
let exitCode = null;
let session;
child.once("exit", (code) => { exitCode = code; });
try {
  ({ session } = await attach(port, (url) => /^https?:\/\/tauri\.localhost\/(?:index\.html)?$/u.test(url)));
  const observedAt = new Date().toISOString();
  session.onEvent((method, params) => {
    if (method === "Runtime.exceptionThrown" || (method === "Runtime.consoleAPICalled" && params?.type === "error") ||
      (method === "Log.entryAdded" && params?.entry?.level === "error")) errors.push({ method, params });
  });
  await session.send("Runtime.enable");
  await session.send("Log.enable");
  await session.send("Page.enable");
  fs.writeFileSync(path.join(evidence, "observation.json"), JSON.stringify({ observedAt, origin: "https://tauri.localhost", connectedData: "synthetic fixture; no remote target" }, null, 2));
  const evaluate = (code) => session.evaluate(code);
  const wait = (code, label) => waitFor(() => evaluate(code), { timeoutMs: 15000, label });
  const dimensions = (width, height) => session.send("Emulation.setDeviceMetricsOverride", { width, height, deviceScaleFactor: 1, mobile: false });
  const screenshot = (name) => session.screenshot(path.join(evidence, `${name}.png`));
  const scope = "document.querySelector('#windows-fixture')";
  const visibleDetail = `[...${scope}.querySelectorAll('.wir-detail, .wir-inspector')].find(element => element.getClientRects().length)`;
  const visibleButtons = `[...${scope}.querySelectorAll('button')].filter(b => b.getClientRects().length && !b.disabled)`;
  const clickText = async (text, exact = true) => {
    const ok = await evaluate(`(() => { const button = ${visibleButtons}.find(b => ${exact ? "b.textContent.trim() ===" : "b.textContent.includes("} ${JSON.stringify(text)}${exact ? "" : ")"}); if (!button) return false; button.focus(); button.click(); return true; })()`);
    if (!ok) throw new Error(`Visible enabled button not found: ${text}`);
    await delay(80);
  };
  const idle = () => wait(`!${scope}.querySelector('.wir-collection-progress')`, "collection settled");
  const module = async (name) => {
    await evaluate(`${scope}.querySelector('button[aria-label=${JSON.stringify(name)}]').click(), true`);
    await delay(180);
    await idle();
  };
  const setInput = async (selector, value) => {
    await evaluate(`(() => { const input = ${scope}.querySelector(${JSON.stringify(selector)}); const proto = input.tagName === 'TEXTAREA' ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype; Object.getOwnPropertyDescriptor(proto, 'value').set.call(input, ${JSON.stringify(value)}); input.dispatchEvent(new Event('input', { bubbles: true })); input.dispatchEvent(new Event('change', { bubbles: true })); return true; })()`);
    await delay(80);
  };
  const chooseRow = async (text) => {
    const ok = await evaluate(`(() => { const row = [...${scope}.querySelectorAll('tbody tr')].find(r => r.getClientRects().length && r.textContent.includes(${JSON.stringify(text)})); if (!row) return false; row.click(); return true; })()`);
    if (!ok) throw new Error(`Row not found: ${text}`);
    await delay(100);
  };

  await wait("document.querySelector('[data-testid=\"welcome-enter-windows\"]') !== null", "welcome view");
  await dimensions(1440, 960);
  await evaluate("document.querySelector('[data-testid=\"welcome-enter-windows\"]').click(), true");
  await wait("document.querySelector('.win-ir-setup') !== null", "real disconnected Windows page");
  const nativeStatus = await evaluate("window.lovelyhawk.windowsIncident({action:'status'}).then(r => ({kind:r.kind, connected:r.status.channelConnected, hasSession: 'sessionId' in r.status}))");
  check("the real bridge returns the validated session-aware status", nativeStatus.kind === "status" && nativeStatus.hasSession, nativeStatus);
  check("the real setup has three steps and no old target card", await evaluate("document.querySelectorAll('.win-ir-step').length === 3 && !document.querySelector('.win-ir-target-card')"));
  const invalidExport = await evaluate("window.lovelyhawk.saveWindowsFile('00000000-0000-4000-8000-000000000099').then(() => false, e => String(e).includes('缓存'))");
  check("a missing native receipt fails before any save dialog", invalidExport);
  const rdpNativeStatus = await evaluate("window.lovelyhawk.windowsRdp({ action: 'status' })");
  check("the real native RDP bridge starts idle without launching a client", rdpNativeStatus.phase === "idle" && rdpNativeStatus.clientId === null);
  await evaluate("document.querySelector('[data-testid=\"open-windows-channel\"]').click(), true");
  check("the bottom status bar opens the channel drawer", await evaluate("document.querySelector('.wir-channel-content').getClientRects().length > 0"));
  await evaluate("document.querySelector('[data-testid=\"open-windows-channel\"]').click(), true");
  await screenshot("01-setup-light");

  await evaluate("document.querySelector('button[aria-label=\"响应方案\"]').click(), true");
  await wait("document.querySelector('.wir-playbook-detail') !== null && !document.querySelector('.wir-setup-view')", "offline playbook view");
  check("the real disconnected workspace offers fourteen offline playbooks", await evaluate("document.querySelectorAll('.wir-playbooks-rail nav button').length === 14 && document.querySelector('.wir-playbook-availability').textContent.includes('当前未连接')"));
  check("offline playbooks disable collection while retaining query preparation", await evaluate("[...document.querySelectorAll('.wir-playbook-actions button')].every(b => b.textContent.startsWith('准备查询') ? !b.disabled : b.disabled)"));
  await screenshot("01a-playbooks-offline-light");

  await evaluate(fs.readFileSync(path.join(runRoot, "fixture", "fixture.js"), "utf8"));
  await evaluate("window.__windowsFixture = WinIrFixture.mount(), true");
  await wait(`${scope}?.textContent.includes('UI-FIXTURE-01')`, "fixture overview");
  await idle();
  check("overview auto-collects only once", await evaluate("window.__windowsFixture.calls.filter(c => c.action === 'collect-overview').length === 1"));
  await screenshot("02-overview-light");

  for (const [name, file] of [["基线配置", "03-baseline"], ["进程分析", "04-processes"], ["网络连接", "05-network"], ["启动项", "06-startup"], ["本地账户", "07-accounts"], ["事件日志", "08-events"], ["调查时间线", "09-timeline"]]) {
    await module(name);
    check(`${name} renders in the native window`, await evaluate(`${scope}.querySelector('.wir-module-head h1').textContent.includes(${JSON.stringify(name)})`));
    await screenshot(file);
  }
  await module("基线配置");
  await chooseRow("本地账户最短口令长度");
  check("new baseline findings show their source and do not offer unsupported quick repair", await evaluate(`${visibleDetail}?.textContent.includes('NetUserModalsGet') && ![...${visibleDetail}.querySelectorAll('button')].some(b => b.textContent.includes('快速修复')) && ${visibleDetail}.textContent.includes('尚未提供自动修复')`));
  await clickText("不适用", false);
  check("not applicable baseline results have a separate filter and neutral label", await evaluate(`(() => { const rows = ${scope}.querySelector('table[aria-label^="基线检查"] tbody'); return rows.rows.length === 1 && rows.textContent.includes('锁定持续时间') && rows.textContent.includes('不适用'); })()`));
  await chooseRow("锁定持续时间");
  check("not applicable detail does not claim a normal risk or offer remediation", await evaluate(`!${visibleDetail}.querySelector('header .wir-badge') && ${visibleDetail}.textContent.includes('当前条件下不执行此项修复') && ![...${visibleDetail}.querySelectorAll('button')].some(b => b.textContent.includes('快速修复'))`));
  await clickText("无法判断", false);
  await chooseRow("登录成功与失败审计");
  check("audit permission gaps remain unknown without a repair shortcut", await evaluate(`${visibleDetail}?.textContent.includes('缺少读取权限') && ${visibleDetail}.textContent.includes('无法判断') && ![...${visibleDetail}.querySelectorAll('button')].some(b => b.textContent.includes('快速修复'))`));
  await screenshot("03a-baseline-permission-gap");
  await clickText("全部", false);
  await evaluate(`(() => { const select = ${scope}.querySelector('select[aria-label="基线类别"]'); select.value = '口令与锁定'; select.dispatchEvent(new Event('change', {bubbles:true})); return true; })()`);
  await delay(100);
  check("baseline categories narrow the list without combining unknown with pass", await evaluate(`${scope}.querySelector('table[aria-label^="基线检查"] tbody').rows.length === 2`));
  await evaluate(`(() => { const select = ${scope}.querySelector('select[aria-label="基线类别"]'); select.value = 'all'; select.dispatchEvent(new Event('change', {bubbles:true})); return true; })()`);
  await delay(100);
  const processRows = `${scope}.querySelector('table[aria-label^="进程分析"] tbody')?.rows.length`;
  const clickTab = async (text) => {
    const ok = await evaluate(`(() => { const tab = [...${scope}.querySelectorAll('[role="tab"]')].find(t => t.getClientRects().length && t.textContent.startsWith(${JSON.stringify(text)})); if (!tab) return false; tab.click(); return true; })()`);
    if (!ok) throw new Error(`Visible tab not found: ${text}`);
    await delay(80);
  };
  const pressKey = async (key, code, windowsVirtualKeyCode) => {
    await session.send("Input.dispatchKeyEvent", { type: "keyDown", key, code, windowsVirtualKeyCode });
    await session.send("Input.dispatchKeyEvent", { type: "keyUp", key, code, windowsVirtualKeyCode });
    await delay(80);
  };
  await module("进程分析");
  const headers = await evaluate(`[...${scope}.querySelectorAll('table[aria-label^="进程分析"] th')].map(th => th.textContent.replace(/[↕↑↓]/gu, '').trim())`);
  check("processes open as a tree with PID and PPID first and risk last", headers[0] === "PID" && headers[1] === "PPID" && headers.at(-1) === "风险" && await evaluate(`${scope}.querySelector('button[aria-label*="System 的子进程"]') !== null`), headers);
  check("process rows carry no decorative marker", await evaluate(`!${scope}.querySelector('.wir-process-mark') && !${scope}.textContent.includes('▣')`));
  check("the process tree is not split across pages", await evaluate(`${processRows} === 240`));
  await clickText("平铺列表");
  check("long flat process lists render only a page", await evaluate(`${processRows} === 100`));
  await clickText("进程树");
  await chooseRow("powershell.exe");
  check("hostile command lines remain plain text", await evaluate(`!${scope}.querySelector('script') && ${scope}.textContent.includes('<script>fixture()</script>')`));
  check("process detail opens only beside the list", await evaluate(`(() => { const detail = ${visibleDetail}; const table = ${scope}.querySelector('.wir-process-table'); return Boolean(detail && table) && !${scope}.querySelector('.wir-process-links') && detail.getBoundingClientRect().left >= table.getBoundingClientRect().right - 1; })()`));
  check("the inspector starts with reasons and a separate raw-fields tab", await evaluate(`${visibleDetail}?.textContent.includes('为什么需要关注') && ${visibleDetail}?.textContent.includes('原始字段')`));
  await screenshot("10a-process-investigation");
  await dimensions(1280, 800); await delay(180);
  check("laptop layout keeps the inspector beside a usable list", await evaluate(`(() => { const detail = ${visibleDetail}.getBoundingClientRect(); const list = ${scope}.querySelector('.wir-process-list').getBoundingClientRect(); return list.width >= 480 && detail.left >= list.right && document.documentElement.scrollWidth <= innerWidth; })()`));
  await screenshot("10b-process-laptop");
  await dimensions(1440, 960); await delay(180);
  await clickText("承载服务", false);
  await clickText("读取网络 / 服务 / DLL");
  await idle();
  check("process inspection carries PID and creation time", await evaluate("window.__windowsFixture.calls.some(c => c.action === 'inspect-process' && c.pid > 0 && c.startTime)"));
  check("selected process services appear in the detail tab", await evaluate(`${visibleDetail}?.textContent.includes('FixtureSvc')`));
  await clickTab("DLL");
  check("loaded modules appear in the detail tab", await evaluate(`${visibleDetail}?.textContent.includes('fixture.dll')`));
  await clickTab("进程链");
  check("the start chain lists the verified ancestors", await evaluate(`(() => { const text = ${visibleDetail}?.textContent ?? ''; return text.includes('System') && text.includes('services.exe') && text.includes('svchost.exe'); })()`));
  await screenshot("10-process-detail");
  await clickText("在网络连接中查看 ↗");
  await idle();
  check("process to network navigation filters by PID", await evaluate(`${scope}.querySelector('.wir-module-head h1').textContent.includes('网络') && [...${scope}.querySelectorAll('tbody')].find(element => element.getClientRects().length)?.rows.length === 1`));
  await clickText("← 返回进程分析");
  check("returning restores the process and its detail", await evaluate(`${scope}.querySelector('.wir-module-head h1').textContent.includes('进程分析') && ${visibleDetail}?.textContent.includes('powershell.exe')`));
  await evaluate(`${scope}.querySelector('table[aria-label^="进程分析"]').focus(), true`);
  await pressKey("ArrowLeft", "ArrowLeft", 37);
  check("left arrow on a leaf selects its parent", await evaluate(`${visibleDetail}?.querySelector('h3')?.textContent === 'svchost.exe'`));
  await pressKey("ArrowLeft", "ArrowLeft", 37);
  check("collapsing keeps descendant risk visible", await evaluate(`${scope}.querySelector('button[aria-label*="svchost.exe 的子进程"]')?.getAttribute('aria-expanded') === 'false' && ${scope}.querySelector('table[aria-label^="进程分析"]').textContent.includes('含 1 个高危')`));
  await screenshot("11-process-tree");
  await pressKey("ArrowRight", "ArrowRight", 39);
  check("right arrow expands the collapsed process", await evaluate(`${scope}.querySelector('button[aria-label*="svchost.exe 的子进程"]')?.getAttribute('aria-expanded') === 'true'`));

  const clickLabel = async (label) => {
    const ok = await evaluate(`(() => { const button = [...${scope}.querySelectorAll('button[aria-label]')].find(b => b.getClientRects().length && !b.disabled && b.getAttribute('aria-label') === ${JSON.stringify(label)}); if (!button) return false; button.click(); return true; })()`);
    if (!ok) throw new Error(`Visible labelled button not found: ${label}`);
    await delay(150);
    await idle();
  };
  const selectedProcess = `${visibleDetail}?.querySelector('h3')?.textContent`;
  const heading = `${scope}.querySelector('.wir-module-head h1').textContent`;
  await module("进程分析");
  await evaluate(`${scope}.querySelector('.wir-process-detail button[aria-label="关闭详情"]')?.click(), true`);
  await module("主机总览");
  await clickLabel("在进程分析中定位 powershell.exe");
  check("an overview finding opens and selects its process", await evaluate(`${heading}.includes('进程分析') && ${selectedProcess} === 'powershell.exe'`));
  check("the cross-link offers the way back to the overview", await evaluate(`${visibleButtons}.some(b => b.textContent.trim() === '← 返回主机总览')`));
  await module("启动项");
  await chooseRow("System Update");
  check("startup detail relates the same executable path to its running process", await evaluate(`(() => { const related = ${visibleDetail}?.querySelector('.wir-related'); return Boolean(related) && related.textContent.includes('powershell.exe · PID 900') && related.textContent.includes('完整路径相同'); })()`));
  check("leaving buttons say where they go", await evaluate(`${visibleButtons}.some(b => b.textContent.trim() === '在文件排查中打开 ↗')`));
  await screenshot("11a-startup-related");
  await clickLabel("在进程分析中定位 powershell.exe · PID 900");
  check("a related record opens in its own module", await evaluate(`${heading}.includes('进程分析') && ${selectedProcess} === 'powershell.exe'`));
  await clickText("← 返回启动项");
  check("returning keeps the startup selection", await evaluate(`${heading}.includes('启动项') && ${visibleDetail}?.textContent.includes('System Update')`));
  await module("调查时间线");
  await setInput('input[aria-label="搜索活动、路径、命令或账户"]', "powershell");
  await chooseRow("进程启动 · powershell.exe");
  await clickText("查看前后 10 分钟");
  check("the timeline narrows to ten minutes around the selected record", await evaluate(`${visibleButtons}.some(b => b.textContent.includes('±10 分钟'))`));
  await screenshot("11b-timeline-around");
  await clickText("在进程分析中定位 ↗");
  check("a timeline record selects the exact process", await evaluate(`${heading}.includes('进程分析') && ${selectedProcess} === 'powershell.exe'`));

  await module("文件排查");
  await evaluate(`${scope}.querySelector('table[aria-label^="目录内容"] th button').click(), true`);
  check("file name sorting changed to descending", await evaluate(`${scope}.querySelector('table[aria-label^="目录内容"] th').getAttribute('aria-sort') === 'descending'`));
  check("folders stay first when sorting in descending order", await evaluate(`[...${scope}.querySelectorAll('tbody')].find(element => element.getClientRects().length)?.rows[0].textContent.includes('Logs')`));
  await chooseRow("Logs");
  await clickText("打开文件夹");
  await idle();
  check("opening a folder commits its successful path", await evaluate(`${scope}.querySelector('input[aria-label="目录路径"]').value.endsWith('\\\\Logs')`));
  await evaluate(`${scope}.querySelector('button[aria-label="后退"]').click(), true`);
  await delay(150); await idle();
  check("history returns to the previous directory", await evaluate(`${scope}.querySelector('input[aria-label="目录路径"]').value === 'C:\\\\Users\\\\Public'`));
  await chooseRow("evidence.txt");
  await clickText("预览前 16 KB");
  await wait(`${scope}.querySelector('.wir-inspector .wir-preview-body')?.textContent === 'data'`, "text preview below the list");
  await screenshot("12-file-text-preview");
  await chooseRow("dropper.exe");
  await clickText("预览前 16 KB");
  await wait(`${scope}.querySelector('.wir-preview-body') !== null`, "PE bytes preview");
  await clickText("属性");
  check("PE preview identifies bounded bytes and a partial read", await evaluate(`${scope}.querySelector('.wir-inspector').textContent.includes('x64')`));
  await screenshot("13-file-pe-preview");
  await clickText("权限与占用排查");
  await clickText("诊断文件访问与驱动关联"); await idle();
  check("file diagnosis displays owner, driver start mode and uncertainty without destructive shortcuts", await evaluate(`${visibleDetail}.textContent.includes('SYSTEM') && ${visibleDetail}.textContent.includes('FixtureDriver') && ${visibleDetail}.textContent.includes('Boot') && ${visibleDetail}.textContent.includes('不代表真实文件占用') && !${visibleDetail}.querySelector('.is-danger')`));
  await screenshot("13a-file-access-driver");
  check("file preset list covers collection locations and driver directories", await evaluate(`${scope}.querySelector('.wir-file-explorer .wir-places').textContent.includes('32') && ${scope}.querySelector('.wir-file-explorer .wir-places').textContent.includes('驱动文件')`));

  await setInput('input[aria-label="目录路径"]', "C:\\denied");
  await evaluate(`${scope}.querySelector('.wir-address').requestSubmit(), true`);
  await delay(200); await idle();
  check("a failed directory read retains the previous listing", await evaluate(`${scope}.textContent.includes('访问被拒绝') && ${scope}.textContent.includes('evidence.txt')`));
  await chooseRow("evidence.txt");
  await clickText("取证拉取", false);
  await idle();
  check("pulling a file opens the receipts tab and labels the unsaved cache", await evaluate(`${scope}.querySelector('.wir-dock.is-expanded.is-files') !== null && ${scope}.querySelector('.wir-transfer-list').textContent.includes('待保存') && !${scope}.querySelector('.wir-command-label').getClientRects().length`));
  check("the dock uses layout space instead of covering the workspace", await evaluate(`(() => { const main = ${scope}.querySelector('.win-ir-main').getBoundingClientRect(); const dock = ${scope}.querySelector('.wir-dock').getBoundingClientRect(); return main.bottom <= dock.top + 1 && dock.bottom <= innerHeight; })()`));
  await clickText("接收与保存");
  await evaluate("window.__windowsFixture.failNext('cancel-save'), true");
  await clickText("另存为…");
  await idle();
  check("cancelled saving retains a pending receipt and the host reminder", await evaluate(`${scope}.querySelector('.wir-transfer-list').textContent.includes('待保存') && ${scope}.querySelector('.wir-host-actions').textContent.includes('1 个文件待保存')`));
  await evaluate("window.__windowsFixture.failNext('save-file'), true");
  await clickText("另存为…");
  await idle();
  check("failed saving keeps the file available for retry", await evaluate(`${scope}.textContent.includes('测试中的保存失败') && ${scope}.querySelector('.wir-transfer-list').textContent.includes('待保存')`));
  await clickText("另存为…");
  await idle();
  check("a verified receipt can be saved and its feedback remains visible", await evaluate(`${scope}.textContent.includes('已另存为 evidence.txt') && ${scope}.querySelector('.wir-transfer-list').textContent.includes('已另存')`));
  check("only a completed save clears the unsaved reminder", await evaluate(`!${scope}.querySelector('.wir-host-actions .wir-unsaved-link')`));
  await screenshot("14-transfers");

  await module("远程桌面");
  await clickText("复制免落地 PowerShell");
  check("desktop copies the exact fileless script without executing it", await evaluate("window.__windowsFixture.copies.at(-1) === \"Write-Output 'fixture only'\" && window.__windowsFixture.calls.every(c=>c.action!=='run-command')"));
  await setInput('input[aria-label="远程桌面地址"]', "192.0.2.10");
  await clickText("连接");
  await wait("window.__windowsFixture.rdpCalls.some(c => c.action === 'start')", "RDP start intent");
  check("RDP viewport stays within the application content", await evaluate(`(() => { const r = ${scope}.querySelector('.wir-rdp-viewport').getBoundingClientRect(); return r.top >= 40 && r.bottom <= innerHeight && r.width >= 160; })()`));
  await screenshot("14a-embedded-desktop-controls");
  await module("文件排查");
  await wait("window.__windowsFixture.rdpCalls.some(c => c.action === 'hide')", "RDP viewport hidden on navigation");
  check("module switching retains the RDP session without displaying over content", await evaluate("window.__windowsFixture.rdpCalls.every(c => c.action !== 'disconnect')"));
  await module("远程桌面");
  await wait(`${scope}.querySelector('input[aria-label="远程桌面地址"]').disabled`, "existing RDP session");
  await clickText("断开远程桌面");
  check("explicit RDP disconnect targets the started client", await evaluate("window.__windowsFixture.rdpCalls.some(c => c.action === 'disconnect' && c.clientId)"));
  await module("注册表");
  check("registry keeps an accessible tree and presets on the left", await evaluate(`${scope}.querySelector('[role="tree"][aria-label="注册表键树"]') !== null && !${scope}.querySelector('.wir-subkeys')`));
  await chooseRow("(默认)");
  check("the unnamed registry value is selectable", await evaluate(`${visibleDetail}?.textContent.includes('空字符串')`));
  await chooseRow("Debugger");
  check("registry detail is below the values and presets stay visible", await evaluate(`(() => { const detail = ${scope}.querySelector('.wir-registry-explorer .wir-inspector'); const table = ${scope}.querySelector('.wir-registry-explorer .wir-master'); return Boolean(detail && table) && detail.getBoundingClientRect().top >= table.getBoundingClientRect().bottom && Boolean(${scope}.querySelector('.wir-registry-navigation')); })()`));
  await clickText("关联线索");
  check("registry related clues retain the evidence qualification", await evaluate(`${visibleDetail}.textContent.includes('仅文件名相同')`));
  await clickText("值数据");
  await screenshot("15-registry");
  await evaluate(`${scope}.querySelector('.wir-registry-explorer button[aria-label="关闭详情"]').click(), true`);
  await delay(80);
  check("closing registry detail returns focus to its list and keeps presets", await evaluate(`Boolean(${scope}.querySelector('.wir-registry-navigation')) && document.activeElement.getAttribute('role') === 'grid'`));
  await chooseRow("Debugger");
  await module("事件日志");
  await chooseRow("账户登录失败");
  check("event detail keeps the real record identifier", await evaluate(`${visibleDetail}?.textContent.includes('983745') && !${scope}.querySelector('script')`));
  await screenshot("16-event-detail");

  await clickTab("命令检查台");
  await setInput('.wir-command-label textarea', "whoami /all");
  await clickTab("通信日志");
  await evaluate(`${scope}.querySelector('.wir-dock-tabs [aria-selected="true"]').focus(), true`);
  await pressKey("ArrowLeft", "ArrowLeft", 37);
  check("dock tabs support keyboard selection and move focus together", await evaluate(`${scope}.querySelector('.wir-dock-tabs [aria-selected="true"]').textContent === '命令检查台' && document.activeElement?.textContent === '命令检查台'`));
  await clickTab("命令检查台");
  check("dock tab changes preserve the command draft", await evaluate(`${scope}.querySelector('.wir-command-label textarea').value === 'whoami /all'`));
  await evaluate(`${scope}.querySelector('select[aria-label="命令预设类别"]').value = '主机与账户', ${scope}.querySelector('select[aria-label="命令预设类别"]').dispatchEvent(new Event('change', { bubbles: true })), true`);
  await delay(100); await clickText("当前权限与令牌");
  await clickText("确认并执行");
  await wait("document.querySelector('[role=\"alertdialog\"], [role=\"dialog\"]') !== null", "command confirmation");
  check("commands do not execute before confirmation", await evaluate("window.__windowsFixture.calls.every(c => c.action !== 'run-command')"));
  await screenshot("17-command-confirmation");
  await session.send("Input.dispatchKeyEvent", { type: "keyDown", key: "Escape", code: "Escape", windowsVirtualKeyCode: 27 });
  await session.send("Input.dispatchKeyEvent", { type: "keyUp", key: "Escape", code: "Escape", windowsVirtualKeyCode: 27 });
  await delay(100);
  check("Escape cancels the command without a remote call", await evaluate("!document.querySelector('[role=\"alertdialog\"], [role=\"dialog\"]') && window.__windowsFixture.calls.every(c => c.action !== 'run-command')"));
  check("command cancellation returns keyboard focus", await evaluate("document.activeElement?.textContent.includes('确认并执行')"));

  const playbookSearch = '.wir-playbooks-rail input[type="search"]';
  const playbookDetail = `${scope}.querySelector('.wir-playbook-detail')`;
  const beforeBrowse = await evaluate("window.__windowsFixture.calls.filter(c => c.action !== 'status').length");
  await module("响应方案");
  check("browsing playbooks does not trigger remote collection", await evaluate(`window.__windowsFixture.calls.filter(c => c.action !== 'status').length === ${beforeBrowse}`));
  await setInput(playbookSearch, "IIS 后门");
  check("playbook search matches multiple terms", await evaluate(`${scope}.querySelectorAll('.wir-playbooks-rail nav button').length === 1`));
  await clickText("IIS 后门与异常站点文件", false);
  check("a filtered scenario list keeps a compact search field", await evaluate(`${scope}.querySelector('.wir-playbooks-rail .wir-search').getBoundingClientRect().height <= 48`));
  await screenshot("24-playbooks-iis-light");
  await clickText("目录 · IIS 配置"); await idle();
  check("playbook directory buttons collect the exact fixed preset", await evaluate("window.__windowsFixture.calls.filter(c => c.action === 'collect-files').at(-1).path === '%SystemRoot%\\\\System32\\\\inetsrv\\\\config'"));
  await clickText("← 返回响应方案");
  check("returning retains playbook selection and search and restores keyboard focus", await evaluate(`${playbookDetail}.getAttribute('aria-label') === 'IIS 后门与异常站点文件' && ${scope}.querySelector(${JSON.stringify(playbookSearch)}).value === 'IIS 后门' && document.activeElement?.getAttribute('aria-current') === 'true'`));
  await setInput(playbookSearch, "<script>not-a-plan</script>");
  check("unmatched search stays plain text and exposes a reset", await evaluate(`${scope}.querySelector('.wir-playbooks-empty').textContent.includes('没有匹配场景') && !${scope}.querySelector('.wir-playbooks script')`));
  await clickText("清空搜索");
  await clickText("启动项、任务与 WMI 驻留", false);
  await clickText("注册表 · 任务缓存"); await idle();
  check("playbook registry buttons retain the fixed TaskCache key", await evaluate("window.__windowsFixture.calls.filter(c => c.action === 'collect-registry').at(-1).keyPath === 'HKLM:\\\\SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Schedule\\\\TaskCache\\\\Tree'"));
  await clickText("← 返回响应方案");
  await clickText("读取WMI 活动"); await idle();
  const playbookLog = await evaluate(`({ category: window.__windowsFixture.calls.filter(c => c.action === 'collect-logs').at(-1).category, scope: ${scope}.querySelector('.wir-logs-layout .wir-query-scope').textContent, visible: ${scope}.querySelector('.wir-logs-layout').getClientRects().length > 0 })`);
  check("playbook event actions select the remote category and show the actual scope", playbookLog.category === "wmi" && playbookLog.scope.includes("WMI 活动") && playbookLog.scope.includes("200 条") && playbookLog.visible, playbookLog);
  await screenshot("24a-playbook-wmi-events");
  await clickText("← 返回响应方案");
  await clickText("复制当前方案");
  check("copied playbooks preserve sources, evidence gaps and guidance status", await evaluate("window.__windowsFixture.copies.at(-1).includes('不是已采集证据或处置结果') && window.__windowsFixture.copies.at(-1).includes('https://attack.mitre.org/techniques/T1546/003/') && window.__windowsFixture.copies.at(-1).includes('带备份、对象核对和恢复的删除流程')"));
  await clickText("准备查询 · WMI 永久事件过滤器");
  check("playbook recommendations preserve the existing command draft", await evaluate(`${scope}.querySelector('.wir-command-suggestion').textContent.includes('WMI 永久事件过滤器') && ${scope}.querySelector('.wir-command-label textarea').value === 'whoami /all' && window.__windowsFixture.calls.every(c => c.action !== 'run-command')`));
  await clickText("保留草稿");
  await module("响应方案");
  await clickText("准备查询 · WMI 永久事件过滤器");
  await clickText("替换草稿为此查询");
  check("accepting a recommendation fills a fixed query without executing it", await evaluate(`${scope}.querySelector('.wir-command-label textarea').value.includes('Get-CimInstance') && ${scope}.querySelector('.wir-command-label textarea').value.includes('__EventFilter') && window.__windowsFixture.calls.every(c => c.action !== 'run-command')`));
  await clickText("确认并执行");
  await wait("document.querySelector('[role=\"alertdialog\"], [role=\"dialog\"]') !== null", "playbook command confirmation");
  check("a playbook query still requires a target-specific command confirmation", await evaluate("document.querySelector('[role=\"alertdialog\"], [role=\"dialog\"]').textContent.includes('UI-FIXTURE-01') && document.querySelector('[role=\"alertdialog\"], [role=\"dialog\"]').textContent.includes('__EventFilter') && window.__windowsFixture.calls.every(c => c.action !== 'run-command')"));
  await session.send("Input.dispatchKeyEvent", { type: "keyDown", key: "Escape", code: "Escape", windowsVirtualKeyCode: 27 });
  await session.send("Input.dispatchKeyEvent", { type: "keyUp", key: "Escape", code: "Escape", windowsVirtualKeyCode: 27 });
  await delay(100);

  await module("响应方案");
  await evaluate("window.__windowsFixture.pauseNext('collect-logs'), true");
  await clickText("读取WMI 活动");
  await wait(`${scope}.querySelector('.wir-collection-progress') !== null`, "playbook collection waiting");
  await evaluate(`${scope}.querySelector('button[aria-label="响应方案"]').click(), true`);
  await delay(100);
  check("a running collection remains visible and blocks new target actions in playbooks", await evaluate(`${scope}.querySelector('.wir-playbook-availability').textContent.includes('当前任务进行中') && [...${playbookDetail}.querySelectorAll('.wir-playbook-actions button')].filter(b => !b.textContent.startsWith('准备查询')).every(b => b.disabled)`));
  await evaluate("window.__windowsFixture.resume(), true"); await idle();
  await evaluate("window.__windowsFixture.failNext('collect-registry'), true");
  await clickText("注册表 · 任务缓存"); await idle();
  check("a failed playbook collection exposes the error and previous snapshot", await evaluate(`${scope}.querySelector('.wir-collection-warnings').textContent.includes('上次采集未完成') && ${scope}.querySelector('.wir-collection-warnings').textContent.includes('上一次成功采集')`));
  await clickText("← 返回响应方案");
  await clickText("注册表 · 任务缓存"); await idle();
  await clickText("← 返回响应方案");

  await module("文件排查");
  await chooseRow("evidence.txt");
  await evaluate("window.__windowsFixture.pauseNext('preview-file'), true");
  await clickText("预览前 16 KB");
  await wait(`${scope}.querySelector('.wir-collection-progress') !== null`, "pending preview");
  const spinBefore = await evaluate(`(() => { const s = [...${scope}.querySelectorAll('.win-ir-spinner')].find(e => e.getClientRects().length); return s ? { transform: getComputedStyle(s).transform, display: getComputedStyle(s).display, reduced: matchMedia('(prefers-reduced-motion: reduce)').matches } : null; })()`);
  await delay(150);
  const spinAfter = await evaluate(`[...${scope}.querySelectorAll('.win-ir-spinner')].filter(e => e.getClientRects().length).map(e => getComputedStyle(e).transform)`);
  check("loading rings are transformable and animate unless reduced motion is enabled", spinBefore && spinBefore.display !== "inline" && (spinBefore.reduced || spinAfter.some(t => t !== spinBefore.transform)));
  await chooseRow("dropper.exe");
  await evaluate("window.__windowsFixture.resume(), true");
  await idle();
  check("a late preview cannot attach itself to a different selected file", await evaluate(`!${scope}.querySelector('.wir-preview-body') && ${visibleDetail}?.textContent.includes('dropper.exe')`));

  await evaluate("window.__windowsFixture.failNext('status'), true");
  await wait(`${scope}.querySelector('.wir-collection-warnings[role="alert"]')?.textContent.includes('暂时无法核实连接状态')`, "temporary status failure");
  check("an unknown connection status does not invite blind registration", await evaluate(`(() => { const register = ${scope}.querySelector('[data-testid="windows-register-plugin"]'); return register === null || register.disabled || !register.getClientRects().length; })()`));
  check("the host bar marks an unknown connection instead of showing a healthy indicator", await evaluate(`${scope}.querySelector('.wir-host-connection.is-offline')?.textContent.includes('连接状态待核实') && Boolean(${scope}.querySelector('.wir-host-connection .status-dot.idle'))`));
  await wait(`!${scope}.querySelector('.wir-session-bar.is-disconnected') && !${scope}.querySelector('.wir-collection-warnings[role="alert"]')`, "same session status recovery");
  check("a temporary status outage preserves the selection for the same session", await evaluate(`${visibleDetail}?.textContent.includes('dropper.exe')`));

  await evaluate("window.__windowsFixture.status.channelConnected = false, true");
  await wait(`${scope}.querySelector('.wir-session-bar.is-disconnected') !== null`, "disconnect warning");
  check("disconnect keeps old evidence in view with a clear stale warning", await evaluate(`!${scope}.querySelector('.wir-setup-view') && ${visibleDetail}?.textContent.includes('dropper.exe') && ${scope}.querySelector('.wir-session-bar').textContent.includes('旧')`));
  await screenshot("18-disconnected-snapshot");
  await clickText("重新接入");
  check("the setup guide is a view of its own, not stacked above a module", await evaluate(`Boolean(${scope}.querySelector('.wir-setup-view .win-ir-setup')) && ${scope}.querySelector('.wir-workspace').hidden && !${scope}.querySelector('.wir-module-head')?.getClientRects().length`));
  await screenshot("18a-setup-view");
  await clickText("← 返回文件排查");
  check("leaving the guide returns to the same record", await evaluate(`!${scope}.querySelector('.wir-setup-view') && ${visibleDetail}?.textContent.includes('dropper.exe')`));
  const overviewCalls = await evaluate("window.__windowsFixture.calls.filter(c => c.action === 'collect-overview').length");
  await evaluate("window.__windowsFixture.reconnect(), true");
  await wait(`window.__windowsFixture.calls.filter(c => c.action === 'collect-overview').length > ${overviewCalls} && ${scope}.textContent.includes('UI-FIXTURE-02')`, "different session overview");
  await idle();
  check("new sessions clear the previous file selection", await evaluate(`!${visibleDetail}`));
  await module("响应方案");
  check("switching targets preserves only the target-independent guidance selection", await evaluate(`${playbookDetail}.getAttribute('aria-label') === '启动项、任务与 WMI 驻留' && ${scope}.querySelector('.wir-host-bar').textContent.includes('UI-FIXTURE-02')`));

  await module("主机总览");
  const beforeBatch = await evaluate("window.__windowsFixture.calls.length");
  await evaluate("window.__windowsFixture.pauseNext('collect-baseline'), true");
  await clickText("采集核心模块", false);
  await wait(`window.__windowsFixture.calls.slice(${beforeBatch}).some(call => call.action === 'collect-baseline')`, "second batch item pending");
  await clickText("停止后续采集");
  await evaluate("window.__windowsFixture.resume(), true");
  await idle();
  check("stopping a batch prevents later collectors from starting", await evaluate(`JSON.stringify(window.__windowsFixture.calls.slice(${beforeBatch}).filter(call => call.action.startsWith('collect-')).map(call => call.action)) === JSON.stringify(['collect-overview', 'collect-baseline'])`));

  const dialog = "document.querySelector('[role=\"alertdialog\"], [role=\"dialog\"]')";
  const escapeDialog = async () => {
    await session.send("Input.dispatchKeyEvent", { type: "keyDown", key: "Escape", code: "Escape", windowsVirtualKeyCode: 27 });
    await session.send("Input.dispatchKeyEvent", { type: "keyUp", key: "Escape", code: "Escape", windowsVirtualKeyCode: 27 });
    await delay(100);
  };
  await module("基线配置");
  await chooseRow("WDigest");
  await clickText("预览配置差异");
  await clickText("预览 1 项配置"); await idle();
  await wait(`${dialog}?.textContent.includes('UI-FIXTURE')`, "baseline immutable preview");
  check("baseline configuration does not write during preview", await evaluate("window.__windowsFixture.calls.every(c => c.action !== 'apply-baseline-plan')"));
  check("new baseline plans focus the readable differences instead of the apply button", await evaluate("document.activeElement?.getAttribute('aria-label') === '配置差异与影响'"));
  await pressKey("Enter", "Enter", 13);
  check("Enter while reading a baseline plan never confirms a write", await evaluate("window.__windowsFixture.calls.every(c => c.action !== 'apply-baseline-plan')"));
  check("the preview names target, original value and impact", await evaluate(`${dialog}.textContent.includes('WDigest') && ${dialog}.textContent.includes('HKLM') && ${dialog}.textContent.includes('重启')`));
  await screenshot("23-baseline-plan");
  await escapeDialog();
  check("cancelling discards the plan without a write", await evaluate("window.__windowsFixture.calls.some(c => c.action === 'discard-baseline-plan') && window.__windowsFixture.calls.every(c => c.action !== 'apply-baseline-plan')"));
  await clickText("预览配置差异"); await clickText("预览 1 项配置"); await idle();
  await clickText("确认配置这 1 项并复核"); await idle();
  check("confirmation executes only the immutable plan and shows verified results", await evaluate(`window.__windowsFixture.calls.some(c => c.action === 'apply-baseline-plan' && typeof c.planId === 'string') && ${dialog}.textContent.includes('配置回读通过')`));
  await screenshot("23a-baseline-remediated");
  await clickText("配置历史 / 恢复"); await idle();
  check("configuration history provides a guarded recovery entry", await evaluate(`${dialog}.textContent.includes('预览恢复差异')`));
  await clickText("预览恢复差异"); await idle();
  await clickText("确认恢复这 1 项并复核"); await idle();
  check("recovery uses a new plan and shows independent readback", await evaluate(`${dialog}.textContent.includes('原值回读通过') && window.__windowsFixture.calls.filter(c => c.action === 'apply-baseline-plan').length === 2`));
  await clickText("重新核查完整基线"); await idle();

  await module("进程分析");
  await chooseRow("powershell.exe");
  await clickText("结束进程");
  await wait(`${dialog} !== null`, "process dialog");
  await clickText("预览影响范围"); await idle();
  check("single-process preview excludes descendants and has no mutation", await evaluate(`${dialog}.textContent.includes('共 1 个') && window.__windowsFixture.calls.every(c=>c.action!=='apply-process-plan')`));
  await escapeDialog();
  await clickText("结束进程树");
  await clickText("预览影响范围"); await idle();
  check("tree preview identifies all processes before confirmation", await evaluate(`${dialog}.textContent.includes('900') && ${dialog}.textContent.includes('999') && ${dialog}.textContent.includes('fixture-child.exe') && window.__windowsFixture.calls.every(c=>c.action!=='apply-process-plan')`));
  check("tree confirmation focuses the readable scope, not the destructive button",await evaluate("document.activeElement?.getAttribute('aria-label') === '完整进程范围'"));
  await session.send("Input.dispatchKeyEvent", {type:"keyDown",key:"Enter",code:"Enter",windowsVirtualKeyCode:13});
  await session.send("Input.dispatchKeyEvent", {type:"keyUp",key:"Enter",code:"Enter",windowsVirtualKeyCode:13});
  check("Enter while reading scope cannot terminate processes",await evaluate("window.__windowsFixture.calls.every(c=>c.action!=='apply-process-plan')"));
  await screenshot("17a-process-tree-plan");
  await clickText("确认结束这 2 个进程"); await idle();
  check("confirmed tree termination sends only the immutable plan and reports every member", await evaluate(`window.__windowsFixture.calls.some(c=>c.action==='apply-process-plan' && typeof c.planId==='string' && !('pid' in c)) && ${dialog}.textContent.includes('已核实退出')`));
  await clickText("刷新进程并复查"); await idle();
  for (const [label,kind] of [["服务","services"],["驱动","drivers"],["计划任务","tasks"]]) {
    await module(label);
    await clickText(`刷新${label}`); await idle();
    const inventoryState=await evaluate(`({requested:window.__windowsFixture.calls.some(c=>c.action==='collect-inventory' && c.kind===${JSON.stringify(kind)}),label:${scope}.querySelector('table[aria-label^="${label}清单"]')?.getAttribute('aria-label')})`);
    check(`${label} has its own bounded inventory request and list`,inventoryState.requested && inventoryState.label===`${label}清单：↑↓ 选择，Enter 打开`,inventoryState);
    await chooseRow(`fixture-${kind}`);
    check(`${label} preserves object details and disabled entries`,await evaluate(`${visibleDetail}.textContent.includes('Synthetic fixture only') && ${scope}.textContent.includes('disabled-${kind}')`));
    await screenshot(`17b-${kind}`);
  }

  await module("启动项");
  const categories=`${scope}.querySelector('nav[aria-label="启动项分类"]')`;
  check("all nineteen startup categories stay visible even with zero records",await evaluate(`${categories}.querySelectorAll('button').length===20 && ${categories}.textContent.includes('KnownDlls') && ${categories}.textContent.includes('Folder Extensions')`));
  await clickText("KnownDlls",false);
  check("an empty startup category retains its coverage explanation",await evaluate(`${scope}.querySelector('.wir-startup-content .wir-empty')?.textContent.includes('没有符合') && ${scope}.querySelector('.wir-startup-content').textContent.includes('已读取所列位置')`));
  await clickText("所有启动项",false);
  await screenshot("27-startup-categories");
  await chooseRow("fixture-services");await clickText("打开系统服务并处置 ↗");await idle();
  check("startup service navigation selects the exact service for action",await evaluate(`${scope}.querySelector('.wir-module-head h1').textContent.includes('服务') && ${visibleDetail}?.textContent.includes('fixture-services') && [...${visibleDetail}.querySelectorAll('button')].some(b=>b.textContent==='停止…')`));
  await module("服务");
  const beforeControl=await evaluate("window.__windowsFixture.calls.filter(c=>c.action==='apply-control').length");
  await clickText("停止…");await idle();
  await wait(`Boolean(${dialog}?.querySelector('[aria-label="完整操作计划"]'))`,"service control preview");
  check("row shortcut previews the selected captured object without writing",await evaluate(`window.__windowsFixture.calls.some(c=>c.action==='plan-control'&&c.operation==='stop'&&typeof c.objectId==='string'&&!('name' in c)) && window.__windowsFixture.calls.filter(c=>c.action==='apply-control').length===${beforeControl}`));
  check("control preview focuses the readable plan",await evaluate("document.activeElement?.getAttribute('aria-label')==='完整操作计划'"));
  await pressKey("Enter","Enter",13);
  check("reading Enter cannot execute a service operation",await evaluate(`window.__windowsFixture.calls.filter(c=>c.action==='apply-control').length===${beforeControl}`));
  await screenshot("28-service-control-plan");await escapeDialog();
  check("cancel discards the control plan and restores the shortcut focus",await evaluate(`!${dialog} && window.__windowsFixture.calls.some(c=>c.action==='discard-control-plan') && document.activeElement?.textContent.includes('停止')`));
  await chooseRow("fixture-services");await clickText("设为手动启动…");await idle();
  await clickText("确认设为手动启动");await idle();
  check("configuration confirmation executes only the plan and exposes guarded recovery",await evaluate(`${dialog}.textContent.includes('可在处置记录') && window.__windowsFixture.calls.filter(c=>c.action==='apply-control').length===${beforeControl+1}`));
  await clickText("刷新清单并复查");await idle();await clickText("处置与恢复记录");await idle();
  await clickText("预览恢复原配置");await idle();
  check("restoration reads a new plan and explains its limited effect",await evaluate(`${dialog}.textContent.includes('恢复配置') && ${dialog}.textContent.includes('不等于业务恢复') && window.__windowsFixture.calls.some(c=>c.action==='plan-control-restore')`));
  await clickText("确认恢复配置");await idle();await clickText("刷新清单并复查");await idle();
  await evaluate("window.__windowsFixture.failNext('plan-control'), true");await clickText("停止…");await idle();
  check("preview failure gives a useful error without an execute button",await evaluate(`${dialog}.textContent.includes('权限不足') && ![...${dialog}.querySelectorAll('button')].some(b=>b.textContent.startsWith('确认'))`));
  await clickText("关闭");
  await module("计划任务");await chooseRow("fixture-tasks");await clickText("立即运行…");await idle();await clickText("确认立即运行");await idle();
  check("task run reports scheduler submission without claiming completion",await evaluate(`${dialog}.textContent.includes('已提交运行') && ${dialog}.textContent.includes('复查任务结果') && !${dialog}.textContent.includes('可在处置记录')`));
  await screenshot("29-task-submitted");await clickText("刷新清单并复查");await idle();
  await clickText("立即运行…");await idle();
  await evaluate("window.__windowsFixture.status.channelConnected=false, true");
  await wait(`${dialog}?.textContent.includes('当前计划失效')`,"control plan connection changed");
  check("disconnect invalidates control confirmation while retaining the readable plan",await evaluate(`[...${dialog}.querySelectorAll('button')].find(b=>b.textContent==='确认立即运行')?.disabled && ${dialog}.querySelector('[aria-label="完整操作计划"]')!==null`));
  await clickText("关闭");await evaluate("window.__windowsFixture.status.channelConnected=true, true");
  await wait(`!${scope}.querySelector('.wir-session-bar.is-disconnected')`,"control session reconnected");
  await module("驱动");await chooseRow("fixture-drivers");
  check("drivers expose guarded start stop and startup configuration actions",await evaluate(`[...${visibleDetail}.querySelectorAll('button')].filter(b=>['启动…','停止…','重启…','设为自动启动…','设为手动启动…','禁用…'].includes(b.textContent)).length===6 && ${visibleDetail}.textContent.includes('引导、系统启动及关键驱动')`));
  await evaluate("window.__windowsFixture.expandTasks(), true");
  for(const [label,kind] of [["服务","services"],["驱动","drivers"],["计划任务","tasks"]]) {
    await module(label);
    if(kind==="tasks"){await clickText("刷新计划任务");await idle();}
    const writeCount=await evaluate("window.__windowsFixture.calls.filter(c=>c.action==='apply-control').length");
    await clickText("详情");await idle();
    await wait(`${dialog}?.querySelector('.wir-inventory-fields')?.textContent.includes('恶意长文本示例')`,`${kind} details loaded`);
    check(`${kind} has a visible details action with real read intent and inert text`,await evaluate(`${dialog}.textContent.includes(${JSON.stringify(kind==="tasks"?"触发器 1":"依赖此对象的服务")}) && !${dialog}.querySelector('.wir-inventory-fields img') && window.__windowsFixture.calls.some(c=>c.action==='inspect-inventory'&&typeof c.objectId==='string') && window.__windowsFixture.calls.filter(c=>c.action==='apply-control').length===${writeCount}`));
    await clickText("复制详情");
    check(`${kind} details copy includes source and full readable fields`,await evaluate("window.__windowsFixture.copies.at(-1).includes('读取时间') && window.__windowsFixture.copies.at(-1).includes('<img src=x')"));
    if(kind==="tasks") {
      await dimensions(820,780);await delay(120);
      check("task details and actions fit a narrow window above the long list",await evaluate(`${dialog}.getBoundingClientRect().right<=innerWidth && ${dialog}.querySelector('footer').getBoundingClientRect().bottom<=innerHeight && document.documentElement.scrollWidth<=innerWidth`));
      await screenshot("31-task-details-narrow");await dimensions(1440,960);await delay(100);
    }
    await screenshot(`32-${kind}-details`);await escapeDialog();
    check(`${kind} closing details returns focus to its visible row button`,await evaluate("document.activeElement?.textContent==='详情'"));
    if(kind==="services") {
      await evaluate("window.__windowsFixture.failNext('inspect-inventory'), true");await clickText("详情");await idle();
      check("failed details retain the earlier collection and explain the failure",await evaluate(`${dialog}.textContent.includes('权限不足') && ${dialog}.textContent.includes('此前采集内容') && ${dialog}.querySelector('.wir-inventory-fields').textContent.includes('fixture-services')`));
      await escapeDialog();
      await evaluate("window.__windowsFixture.pauseNext('inspect-inventory'), true");await clickText("详情");
      check("a pending detail read can be closed without enabling changes",await evaluate(`${dialog}.textContent.includes('最长等待 45 秒') && [...${dialog}.querySelectorAll('button')].find(b=>b.textContent==='删除注册项…')?.disabled`));
      await clickText("关闭详情");await evaluate("window.__windowsFixture.resume(), true");await idle();
      check("late detail responses do not reopen a closed window",await evaluate(`!${dialog}`));
    }
    if(kind==="tasks") {
      const longTaskLayout=await evaluate(`(()=>{const rows=[...${scope}.querySelectorAll('.wir-inventory tbody tr')].filter(r=>r.getClientRects().length);const row=rows.find(r=>r.textContent.includes('长列表任务'));if(!row)return {found:false,rows:rows.length};const description=row.querySelector('.wir-inventory-name small'),style=getComputedStyle(description),singleLine=description.cloneNode(false);singleLine.textContent='测';Object.assign(singleLine.style,{position:'absolute',visibility:'hidden',display:'block',webkitLineClamp:'unset',width:description.clientWidth+'px'});description.parentElement.append(singleLine);const lineHeight=singleLine.getBoundingClientRect().height;singleLine.remove();return {found:true,rows:rows.length,height:description.getBoundingClientRect().height,lineHeight,clamp:style.webkitLineClamp,display:style.display};})()`);
      check("long task descriptions remain bounded in the list",longTaskLayout.found && longTaskLayout.rows===100 && longTaskLayout.lineHeight>0 && longTaskLayout.height<=2*longTaskLayout.lineHeight+1,longTaskLayout);
      await screenshot("34-tasks-long-list-actions");
      await chooseRow("fixture-tasks");await evaluate(`[...${scope}.querySelectorAll('.wir-inventory table')].find(t=>t.getClientRects().length).focus(), true`);await pressKey("Enter","Enter",13);await idle();
      check("Enter on the selected task opens details without running it",await evaluate(`${dialog}?.textContent.includes('计划任务详情') && window.__windowsFixture.calls.filter(c=>c.action==='apply-control').length===${writeCount}`));
      await evaluate("window.__windowsFixture.status.channelConnected=false, true");await wait(`${dialog}?.textContent.includes('未连接原会话')`,"details disconnect");
      check("disconnected details preserve observations and disable every target action",await evaluate(`${dialog}.querySelector('.wir-inventory-fields')!==null && [...${dialog}.querySelectorAll('button')].filter(b=>['删除注册项…','立即运行…','重新读取详情'].includes(b.textContent)).every(b=>b.disabled)`));
      await evaluate("window.__windowsFixture.status.channelConnected=true, true");await wait(`!${scope}.querySelector('.wir-session-bar.is-disconnected')`,"details reconnect");await escapeDialog();
    }
    await clickText("操作 ▾");
    check(`${kind} action chooser exposes deletion without writing`,await evaluate(`${dialog}.textContent.includes('删除注册项') && window.__windowsFixture.calls.filter(c=>c.action==='apply-control').length===${writeCount}`));
    await evaluate(`[...${dialog}.querySelectorAll('button')].find(b=>b.textContent==='删除注册项…').click(), true`);await idle();
    await wait(`Boolean(${dialog}?.querySelector('[aria-label="完整操作计划"]') && ${dialog}?.querySelector('input[type="checkbox"]'))`,`${kind} deletion preview`);
    check(`${kind} deletion starts unacknowledged with no irreversible default`,await evaluate(`!${dialog}.querySelector('input[type="checkbox"]').checked && [...${dialog}.querySelectorAll('button')].find(b=>b.textContent==='确认删除注册项')?.disabled && ${dialog}.textContent.includes('执行文件保留') && ${dialog}.textContent.includes('不能一键恢复')`));
    await pressKey("Enter","Enter",13);
    check(`${kind} preview Enter cannot trigger deletion`,await evaluate(`window.__windowsFixture.calls.filter(c=>c.action==='apply-control').length===${writeCount}`));
    await evaluate(`${dialog}.querySelector('input[type="checkbox"]').click(), true`);await delay(60);
    await screenshot(`33-${kind}-delete-preview`);
    await clickText("确认删除注册项");await idle();
    check(`${kind} deletion executes once and never offers fake restore`,await evaluate(`window.__windowsFixture.calls.filter(c=>c.action==='apply-control').length===${writeCount+1} && !${dialog}.textContent.includes('可在处置记录')`));
    await clickText("刷新清单并复查");await idle();
    check(`${kind} refreshed list no longer contains the deleted registration`,await evaluate(`![...${scope}.querySelectorAll('.wir-inventory tbody tr')].some(r=>r.textContent.includes(${JSON.stringify('fixture-')}+${JSON.stringify(kind)}))`));
  }
  await module("启动项");await dimensions(820,780);await delay(180);
  check("startup categories remain reachable in a narrow window without page overflow",await evaluate(`document.documentElement.scrollWidth<=innerWidth && ${categories}.scrollWidth>${categories}.clientWidth && ${scope}.querySelector('table[aria-label^="启动项与持久化"]').getBoundingClientRect().width>400`));
  await screenshot("30-startup-narrow");await dimensions(1440,960);await delay(100);

  await module("文件排查");
  await chooseRow("evidence.txt");
  await clickText("删除文件");
  await wait(`${dialog} !== null`, "file deletion confirmation");
  check("file deletion does not run before confirmation", await evaluate("window.__windowsFixture.calls.every(c => c.action !== 'delete-file')"));
  await escapeDialog();
  check("cancelling file deletion keeps the listing", await evaluate(`!${dialog} && window.__windowsFixture.calls.every(c => c.action !== 'delete-file') && ${scope}.textContent.includes('evidence.txt')`));
  await clickText("删除文件");
  await wait(`${dialog} !== null`, "file deletion confirmation again");
  await clickText("确认永久删除");
  await idle();
  check("confirmed file deletion re-reads the directory without the file", await evaluate(`window.__windowsFixture.calls.some(c => c.action === 'delete-file' && c.path.endsWith('evidence.txt')) && !${scope}.querySelector('tbody')?.textContent.includes('evidence.txt')`));
  await screenshot("23b-file-deleted");

  await module("注册表");
  await chooseRow("Debugger");
  await clickText("删除键值…");
  await wait(`${dialog} !== null`, "registry value deletion confirmation");
  check("registry deletion does not run before confirmation", await evaluate("window.__windowsFixture.calls.every(c => c.action !== 'delete-registry-value')"));
  await clickText("确认删除键值");
  await idle();
  check("confirmed registry deletion re-reads the key without the value", await evaluate(`window.__windowsFixture.calls.some(c => c.action === 'delete-registry-value' && c.valueName === 'Debugger') && !${scope}.querySelector('tbody')?.textContent.includes('Debugger')`));

  await module("进程分析");
  await evaluate(`${scope}.querySelector('table[aria-label^="进程分析"]').focus(), true`);
  await session.send("Input.dispatchKeyEvent", { type: "keyDown", key: "ArrowDown", code: "ArrowDown", windowsVirtualKeyCode: 40 });
  await session.send("Input.dispatchKeyEvent", { type: "keyUp", key: "ArrowDown", code: "ArrowDown", windowsVirtualKeyCode: 40 });
  check("arrow keys select a row and expose details", await evaluate(`${visibleDetail} !== undefined`));
  await module("文件排查");
  await evaluate("window.__windowsFixture.pauseNext('collect-files'), true");
  await setInput('input[aria-label="目录路径"]', "C:\\old-session-only");
  await evaluate(`${scope}.querySelector('.wir-address').requestSubmit(), true`);
  await wait(`${scope}.querySelector('.wir-collection-progress') !== null`, "pending directory read");
  await evaluate("window.__windowsFixture.reconnect('UI-FIXTURE-03'), true");
  await evaluate("window.__windowsFixture.resume(), true");
  await wait(`${scope}.textContent.includes('已清空旧结果')`, "a different host after reconnect clears the old results");
  await wait(`${scope}.querySelector('table[aria-label^="目录内容"]') !== null && !${scope}.querySelector('.wir-collection-progress')`, "new session directory");
  check("a late old-session listing cannot replace the new directory", await evaluate(`${scope}.querySelector('input[aria-label="目录路径"]').value === 'C:\\\\Users\\\\Public' && ${scope}.querySelector('button[aria-label="后退"]').disabled`));
  await chooseRow("evidence.txt");
  const filesCollected = await evaluate(`${scope}.querySelector('.wir-collected').textContent`);
  await evaluate("window.__windowsFixture.reconnect('UI-FIXTURE-03'), true");
  await wait(`${scope}.textContent.includes('保留了重连前采集的结果')`, "same host after reconnect");
  check("reconnecting to the same host keeps results, times and the selection", await evaluate(`${scope}.querySelector('.wir-collected').textContent === ${JSON.stringify(filesCollected)} && ${visibleDetail}?.textContent.includes('evidence.txt')`), filesCollected);

  await evaluate("document.querySelector('[data-testid=\"open-theme-picker\"]').click(), true");
  await evaluate("document.querySelector('[data-testid=\"theme-card-shenhai\"]').click(), true");
  await wait("document.documentElement.dataset.theme === 'shenhai'", "dark theme applied");
  await module("主机总览"); await screenshot("19-overview-dark");
  await module("文件排查"); await chooseRow("dropper.exe"); await screenshot("20-files-dark");
  await dimensions(960, 780); await delay(180);
  const overflow = await evaluate(`({ width: innerWidth, document: document.documentElement.scrollWidth, elements: [...document.querySelectorAll('body *')].filter(e => {const r=e.getBoundingClientRect(); return r.width > 0 && r.right > innerWidth + 1 && getComputedStyle(e).position !== 'fixed'; }).slice(0,15).map(e=>({tag:e.tagName,class:e.className,right:e.getBoundingClientRect().right,width:e.getBoundingClientRect().width})) })`);
  check("narrow window has no document-wide horizontal overflow", overflow.document <= overflow.width, overflow);
  await screenshot("21-files-narrow-dark");
  await module("进程分析");
  await screenshot("22-processes-narrow-dark");
  check("narrow windows automatically use the navigation rail", await evaluate(`${scope}.querySelector('.windows-incident-page.is-rail') !== null`));
  await chooseRow("services.exe");
  check("the narrow inspector has its own readable view and reachable footer", await evaluate(`(() => { const detail = ${visibleDetail}; const list = ${scope}.querySelector('.wir-process-list'); const footer = detail?.querySelector('footer').getBoundingClientRect(); return Boolean(detail) && getComputedStyle(list).display === 'none' && footer.bottom <= ${scope}.querySelector('.win-ir-main').getBoundingClientRect().bottom + 1; })()`));
  await screenshot("22a-process-narrow-inspector");
  await clickLabel("关闭详情");
  check("closing the narrow inspector restores the table and keyboard focus", await evaluate(`getComputedStyle(${scope}.querySelector('.wir-process-list')).display !== 'none' && document.activeElement?.getAttribute('role') === 'grid'`));
  check("collapsed navigation retains all investigation names and the desktop entry", await evaluate(`${scope}.querySelectorAll('.win-ir-nav-item[aria-label]').length === 14 && Boolean(${scope}.querySelector('button[aria-label="远程桌面"]'))`));
  await screenshot("23-navigation-rail");
  await module("响应方案");
  await setInput(playbookSearch, "");
  await clickText("驱动异常与删除受阻", false);
  await screenshot("25-playbooks-drivers-narrow-dark");
  check("playbooks fit the narrow dark desktop and retain four stages", await evaluate(`document.documentElement.scrollWidth <= innerWidth && ${playbookDetail}.querySelectorAll('.wir-playbook-steps > li').length === 4 && ${playbookDetail}.textContent.includes('没有绕过系统保护')`));
  await dimensions(720, 780); await delay(180);
  check("small playbook windows stack the scenario list above readable guidance", await evaluate(`(() => { const rail = ${scope}.querySelector('.wir-playbooks-rail').getBoundingClientRect(); const detail = ${playbookDetail}.getBoundingClientRect(); return detail.top >= rail.bottom - 1 && detail.width > 500 && document.documentElement.scrollWidth <= innerWidth; })()`));
  await screenshot("26-playbooks-small-dark");
  await evaluate(`${playbookDetail}.querySelector('.wir-playbook-sources').open = true, ${playbookDetail}.querySelector('.wir-playbook-sources button').scrollIntoView(), true`);
  await clickText("复制资料链接");
  check("source references remain reachable and copy their verified URL in small windows", await evaluate("window.__windowsFixture.copies.at(-1) === 'https://learn.microsoft.com/en-us/sysinternals/downloads/handle'"));
  await evaluate("window.__windowsFixture.status.channelConnected = false, true");
  await wait(`${scope}.querySelector('.wir-playbook-availability').textContent.includes('当前未连接')`, "playbook disconnect");
  check("disconnect retains the selected guidance and disables target actions", await evaluate(`${playbookDetail}.getAttribute('aria-label') === '驱动异常与删除受阻' && [...${playbookDetail}.querySelectorAll('.wir-playbook-actions button')].every(b => b.textContent.startsWith('准备查询') ? !b.disabled : b.disabled)`));
  check("no browser runtime or console errors", errors.length === 0, errors);
  await evaluate("window.__windowsFixture.unmount(), true");
  await evaluate("document.querySelector('[data-testid=\"window-close\"]').click(), true");
  await waitFor(() => exitCode !== null, { timeoutMs: 15000, label: "clean exit" });
  check("the native window exits cleanly", exitCode === 0);
} catch (error) {
  check("probe completed", false, error instanceof Error ? error.message : String(error));
  if (session) {
    await session.screenshot(path.join(evidence, "failure.png")).catch(() => undefined);
    const text = await session.evaluate("document.body.innerText").catch(() => "");
    fs.writeFileSync(path.join(evidence, "failure.txt"), String(text));
  }
} finally {
  if (exitCode === null) child.kill();
  session?.close();
  fs.writeFileSync(path.join(evidence, "console.json"), JSON.stringify(errors, null, 2));
  fs.writeFileSync(path.join(evidence, "checks.json"), JSON.stringify(checks, null, 2));
  fs.writeFileSync(path.join(evidence, "host.log"), output.join(""));
}
console.log(`${checks.every((item) => item.ok) ? "PASS" : "FAIL"}: ${checks.filter((item) => item.ok).length}/${checks.length}; evidence in ${evidence}`);
process.exitCode = checks.every((item) => item.ok) ? 0 : 1;
