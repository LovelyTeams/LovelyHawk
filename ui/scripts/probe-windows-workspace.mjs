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
  const visibleDetail = `[...${scope}.querySelectorAll('.wir-detail')].find(element => element.getClientRects().length)`;
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
  await wait(`${scope}.querySelector('.wir-modal .wir-preview-body')?.textContent === 'data'`, "text preview in a dialog");
  await screenshot("12-file-text-preview");
  await chooseRow("dropper.exe");
  await clickText("预览前 16 KB");
  await wait(`${scope}.querySelector('.wir-pe') !== null`, "PE preview");
  check("PE preview identifies bounded bytes and a partial read", await evaluate(`${scope}.querySelector('.wir-preview').textContent.includes('512') && ${scope}.querySelector('.wir-pe').textContent.includes('x64')`));
  await screenshot("13-file-pe-preview");
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
  check("registry uses an accessible tree and right-hand shortcuts", await evaluate(`${scope}.querySelector('[role="tree"][aria-label="注册表键树"]') !== null && !${scope}.querySelector('.wir-subkeys')`));
  await chooseRow("(默认)");
  check("the unnamed registry value is selectable", await evaluate(`${visibleDetail}?.textContent.includes('空字符串')`));
  await chooseRow("Debugger");
  check("the registry value detail replaces the shortcut column on the right", await evaluate(`Boolean(${scope}.querySelector('.wir-registry-side .wir-detail')) && !${scope}.querySelector('.wir-registry-shortcuts') && ${scope}.querySelector('.wir-registry-side').textContent.includes('仅文件名相同')`));
  await screenshot("15-registry");
  await evaluate(`${scope}.querySelector('.wir-registry-side button[aria-label="关闭详情"]').click(), true`);
  await delay(80);
  check("closing the value detail restores the registry shortcuts", await evaluate(`Boolean(${scope}.querySelector('.wir-registry-shortcuts'))`));
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
  await clickText("whoami /all");
  await clickText("确认并执行");
  await wait("document.querySelector('[role=\"alertdialog\"], [role=\"dialog\"]') !== null", "command confirmation");
  check("commands do not execute before confirmation", await evaluate("window.__windowsFixture.calls.every(c => c.action !== 'run-command')"));
  await screenshot("17-command-confirmation");
  await session.send("Input.dispatchKeyEvent", { type: "keyDown", key: "Escape", code: "Escape", windowsVirtualKeyCode: 27 });
  await session.send("Input.dispatchKeyEvent", { type: "keyUp", key: "Escape", code: "Escape", windowsVirtualKeyCode: 27 });
  await delay(100);
  check("Escape cancels the command without a remote call", await evaluate("!document.querySelector('[role=\"alertdialog\"], [role=\"dialog\"]') && window.__windowsFixture.calls.every(c => c.action !== 'run-command')"));
  check("command cancellation returns keyboard focus", await evaluate("document.activeElement?.textContent.includes('确认并执行')"));

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
  await clickText("快速修复");
  await wait(`${dialog} !== null`, "baseline remediation confirmation");
  check("baseline remediation does not run before confirmation", await evaluate("window.__windowsFixture.calls.every(c => c.action !== 'remediate-baseline')"));
  check("the remediation confirmation names the target and the check", await evaluate(`${dialog}.textContent.includes('WDigest') && ${dialog}.textContent.includes('UI-FIXTURE')`));
  await escapeDialog();
  check("cancelling leaves the baseline item unchanged", await evaluate("window.__windowsFixture.calls.every(c => c.action !== 'remediate-baseline')"));
  await clickText("快速修复");
  await wait(`${dialog} !== null`, "baseline remediation confirmation again");
  await clickText("确认修复并复核");
  await idle();
  check("confirmed remediation re-collects the baseline", await evaluate(`window.__windowsFixture.calls.some(c => c.action === 'remediate-baseline' && c.ruleId === 'wdigest') && ${scope}.textContent.includes('复核')`));
  await screenshot("23a-baseline-remediated");

  await module("进程分析");
  await chooseRow("powershell.exe");
  await clickText("结束进程");
  await wait(`${dialog} !== null`, "process kill confirmation");
  check("process termination does not run before confirmation", await evaluate("window.__windowsFixture.calls.every(c => c.action !== 'kill-process')"));
  check("the kill confirmation identifies pid and start time", await evaluate(`${dialog}.textContent.includes('900') && ${dialog}.textContent.includes('powershell.exe')`));
  await clickText("确认结束进程");
  await idle();
  check("confirmed termination binds pid and start time then re-collects", await evaluate("window.__windowsFixture.calls.some(c => c.action === 'kill-process' && c.pid === 900 && typeof c.startTime === 'string' && c.startTime.length > 0)"));

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
  await clickText("删除键值");
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
  check("collapsed navigation retains all investigation names and the desktop entry", await evaluate(`${scope}.querySelectorAll('.win-ir-nav-item[aria-label]').length === 10 && Boolean(${scope}.querySelector('button[aria-label="远程桌面"]'))`));
  await screenshot("23-navigation-rail");
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
