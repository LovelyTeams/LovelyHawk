// Actual debug WebView2, production components/styles, synthetic API data.
import fs from "node:fs";
import path from "node:path";
import { randomUUID } from "node:crypto";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { build } from "vite";
import react from "@vitejs/plugin-react";
import { attach, delay, waitFor } from "./cdp.mjs";

const ui = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const repository = path.dirname(ui);
const runRoot = path.join(repository, "target/desktop-debug", `command-workbench-${randomUUID()}`);
const evidence = path.join(runRoot, "evidence");
fs.mkdirSync(evidence, { recursive: true });
await build({ root: ui, configFile: false, plugins: [react()], logLevel: "warn",
  define: { "process.env.NODE_ENV": JSON.stringify("production") },
  build: { outDir: path.join(runRoot, "fixture"), emptyOutDir: false,
    lib: { entry: path.join(ui, "scripts/command-workbench-fixture.tsx"), name: "CommandFixture", formats: ["iife"], fileName: () => "fixture.js" } } });
const report = { syntheticData: true, checks: [], errors: [] };
function check(name, passed, detail) { report.checks.push({ name, passed: Boolean(passed), detail }); console.log(`${passed ? "PASS" : "FAIL"} ${name}`); }
const port = 12600 + Math.floor(Math.random() * 200);
const child = spawn(process.env.LOVELYHAWK_DESKTOP_BIN ?? path.join(repository, "target/debug/lovelyhawk.exe"), [], {
  env: { ...process.env, LOVELYHAWK_DEBUG_PORT: String(port), LOVELYHAWK_ARCHIVE_ROOT: runRoot },
  windowsHide: true, stdio: ["ignore", "pipe", "pipe"],
});
const output = [];
child.stdout.on("data", chunk => output.push(String(chunk))); child.stderr.on("data", chunk => output.push(String(chunk)));
let exited = false; let session;
child.on("exit", () => { exited = true; });
try {
  ({ session } = await attach(port, url => /^https:\/\/tauri\.localhost\/(?:index\.html)?$/u.test(url)));
  report.observedAt = new Date().toISOString();
  session.onEvent((method, params) => {
    if (method === "Runtime.exceptionThrown" || method === "Runtime.consoleAPICalled" && params?.type === "error" || method === "Log.entryAdded" && params?.entry?.level === "error") report.errors.push({ method, params });
  });
  await session.send("Runtime.enable"); await session.send("Log.enable"); await session.send("Page.enable");
  const evaluate = expression => session.evaluate(expression);
  const wait = (expression, label) => waitFor(() => evaluate(expression), { timeoutMs: 12000, label });
  const scope = "document.querySelector('#command-workbench-fixture')";
  const text = `${scope}.textContent`;
  const click = async (label, aria = false) => {
    const found = await evaluate(`(() => { const item = [...${scope}.querySelectorAll('button')].find(button =>
      ${aria ? "button.getAttribute('aria-label')" : "button.textContent.trim()"} === ${JSON.stringify(label)} && !button.disabled);
      if (!item) return false; item.click(); return true; })()`);
    if (!found) throw new Error(`Button missing/disabled: ${label}`);
    await delay(80);
  };
  const search = async value => {
    await evaluate(`(() => { const input = ${scope}.querySelector('[aria-label="搜索命令"]');
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(input, ${JSON.stringify(value)});
      input.dispatchEvent(new Event('input', {bubbles:true})); })()`);
    await delay(100);
  };
  const render = async (binding = "fixture-a", options = {}, reset = true, extra = {}) => {
    await evaluate(`${reset ? "window.commandFixture.reset();" : ""}window.commandFixture.render(${JSON.stringify(binding)},${JSON.stringify(options)},${JSON.stringify(extra)}); true`);
    await wait(`${scope}.querySelector('${binding === null ? ".emergency-commands-disconnected" : ".emergency-commands-workbench"}') !== null`, "workbench mounted");
  };
  const screenshot = name => session.screenshot(path.join(evidence, `${name}.png`));
  await wait("document.querySelector('[data-testid=welcome-view]') !== null", "real app welcome");
  await evaluate("document.querySelector('[data-testid=window-minimize]').click(); true");
  const registry = await evaluate("window.lovelyhawk.bootstrap().then(value => value.pages)");
  check("one original command workbench route; no second investigation page", registry.length === 14 &&
    registry.find(page => page.id === "emergency-commands")?.title === "命令工作台" && !registry.some(page => page.id === "response-engine"));
  check("dedicated response engine API removed from the real host bridge", await evaluate("!('responseEngine' in window.lovelyhawk)"));
  await evaluate(fs.readFileSync(path.join(runRoot, "fixture/fixture.js"), "utf8"));
  for (const css of fs.readdirSync(path.join(ui, "dist/assets")).filter(name => name.endsWith(".css"))) {
    await evaluate(`(() => { const link=document.createElement('link'); link.rel='stylesheet'; link.href=${JSON.stringify(`/assets/${css}`)}; document.head.append(link); })()`);
  }
  await evaluate("window.commandFixture = CommandFixture.mount(); true");
  await session.send("Emulation.setDeviceMetricsOverride", { width: 1360, height: 900, deviceScaleFactor: 1, mobile: false });
  await render();
  check("integrated categories without checkbox picker or automatic tab", await evaluate(`!${scope}.querySelector('input[type=checkbox]') && !${scope}.querySelector('[role=tablist]') && ${text}.includes('排查命令包装器') && ${text}.includes('PAM 认证规则与变更')`));
  await screenshot("00-workbench-overview");
  await search("包装器");
  await click("快速执行 持久化检查 的 1 项调查", true);
  await wait(`${text}.includes('已完成 1 项')`, "filtered group complete");
  check("filtered group executes exactly its advertised one item", await evaluate("window.commandFixture.calls.length === 1 && window.commandFixture.calls[0].command.endsWith('-wrapper')"));
  check("hostile output stays text and gaps stay visible", await evaluate(`!${scope}.querySelector('img') && ${text}.includes('<img src=x onerror=steal()>') && ${text}.includes('权限不足')`));
  await click("关注与缺口");
  check("nested result view uses an underline without a filled button", await evaluate(`(() => {
    const group = ${scope}.querySelector('[aria-label="结果显示范围"]');
    const selected = group.querySelector('[aria-pressed="true"]');
    return group.classList.contains('view-tabs-underline') && getComputedStyle(selected).borderTopWidth === '0px' &&
      getComputedStyle(selected).backgroundColor === 'rgba(0, 0, 0, 0)' && getComputedStyle(selected, '::after').height === '2px';
  })()`));
  check("focused output keeps gaps and original line numbers", await evaluate(`!${scope}.querySelector('.emergency-command-output').textContent.includes('普通清单信息') && ${scope}.querySelector('.emergency-command-output').textContent.includes('权限不足') && ${scope}.querySelector('.emergency-command-gutter .is-abnormal').textContent === '3'`));
  await screenshot("01-integrated-results");
  await evaluate(`(() => { const select = ${scope}.querySelector('select'); select.value = 'container-fixture-a'; select.dispatchEvent(new Event('change',{bubbles:true})); })()`);
  await wait(`${scope}.querySelector('.emergency-command-result') === null`, "old host output cleared on location change");
  check("changing execution location clears observations from the previous place", await evaluate(`${text}.includes('尚未执行') && !${text}.includes('fixture-a |')`));

  await render("fixture-a", { delay: true });
  await click("快速执行 持久化检查 的 2 项调查", true);
  await wait("window.commandFixture.pendingCount() === 1", "first group item pending");
  check("running group locks list selection, refresh, filter and target location", await evaluate(`${scope}.querySelector('[aria-label="搜索命令"]').disabled && ${scope}.querySelector('.emergency-commands-reload').disabled && ${scope}.querySelector('select').disabled && [...${scope}.querySelectorAll('.emergency-command-group-items button')].every(button => button.disabled)`));
  await click("停止后续检查");
  check("stop explicitly waits for the current command", await evaluate(`${text}.includes('当前命令仍会等到返回或超时') && ${text}.includes('正在等待当前检查结束')`));
  await evaluate("window.commandFixture.resolveOne(); true");
  await wait(`${text}.includes('完成 1/2 项，1 项未执行')`, "stopped group");
  check("stopped group retains the first result and never starts the second", await evaluate(`window.commandFixture.calls.length === 1 && ${text}.includes('fixture-a |') && !${scope}.querySelector('[aria-label="搜索命令"]').disabled`));
  await screenshot("02-stopped-group");

  await render("fixture-a", { delay: true });
  await click("运行只读调查");
  await wait("window.commandFixture.pendingCount() === 1", "single check pending");
  check("single run also keeps selection stable", await evaluate(`[...${scope}.querySelectorAll('.emergency-command-group-items button')].every(button => button.disabled)`));
  await render("fixture-b", {}, false);
  await evaluate("window.commandFixture.resolveOne(); true");
  await delay(100);
  check("late result from previous target is discarded", await evaluate(`!${text}.includes('fixture-a |') && !${scope}.querySelector('.emergency-command-run').disabled`));

  await render("fixture-b", { fail: true });
  await click("运行只读调查");
  await wait(`${scope}.querySelector('.emergency-command-error') !== null`, "failure feedback");
  check("failed read is visible and can be retried", await evaluate(`${text}.includes('内置命令未能完成') && !${scope}.querySelector('.emergency-command-run').disabled`));
  await render("fixture-b", { empty: true });
  await click("运行只读调查");
  await wait(`${text}.includes('命令没有输出')`, "empty result");
  check("empty output does not claim safety", await evaluate(`${text}.includes('不能据此确认没有风险')`));

  await render("fixture-b", { long: true });
  await click("运行只读调查");
  await wait(`${scope}.querySelector('.emergency-command-result') !== null`, "long result");
  await session.send("Emulation.setDeviceMetricsOverride", { width: 760, height: 800, deviceScaleFactor: 1, mobile: false });
  await delay(150);
  check("narrow workbench uses the available width without page overflow", await evaluate(`${scope}.scrollWidth <= ${scope}.clientWidth + 1 && ${scope}.clientWidth >= window.innerWidth - 40 && ${scope}.querySelector('.emergency-command-result').getBoundingClientRect().right <= window.innerWidth`));
  await screenshot("03-narrow-long-output");
  await evaluate(`${scope}.querySelector('.emergency-command-result-tools button:last-child').focus(); true`);
  await session.send("Input.dispatchKeyEvent", { type: "keyDown", key: " ", code: "Space", windowsVirtualKeyCode: 32 });
  await session.send("Input.dispatchKeyEvent", { type: "keyUp", key: " ", code: "Space", windowsVirtualKeyCode: 32 });
  await delay(80);
  check("result display switch works by keyboard", await evaluate("document.activeElement.getAttribute('aria-pressed') === 'true'"));
  if (process.env.LOVELYHAWK_OBSERVATION_REPORT) {
    const sourceReport = JSON.parse(fs.readFileSync(process.env.LOVELYHAWK_OBSERVATION_REPORT, "utf8"));
    if (sourceReport.failure || sourceReport.checks.some(item => !item.passed)) throw new Error("Collector report did not pass");
    const observations = Object.fromEntries([
      ["history", "history reports exact credential locations without commands or passwords"],
      ["credential", "site secrets and backups are clues, ordinary archives and non-site dumps are neutral"],
      ["web", "PHP request execution, decoder execution and JSP/ASP direct calls have locations"],
    ].map(([key, name]) => {
      const item = sourceReport.checks.find(candidate => candidate.name === name);
      if (typeof item?.stdout !== "string") throw new Error(`Missing collector evidence: ${name}`);
      return [key, { stdout: item.stdout, status: item.status }];
    }));
    report.collectorReport = process.env.LOVELYHAWK_OBSERVATION_REPORT;
    await session.send("Emulation.setDeviceMetricsOverride", { width: 1360, height: 900, deviceScaleFactor: 1, mobile: false });
    for (const [key, title, expected] of [
      ["history", "命令历史文件", "原文未输出"],
      ["credential", "凭据与站点备份文件", "站点映射与访问控制"],
      ["web", "站点可疑代码特征", "请求参数直接进入"],
    ]) {
      await render("fixture-a", { observations });
      await search(title);
      const selected = await evaluate(`(() => { const button=[...${scope}.querySelectorAll('.emergency-command-group-items button')].find(item=>item.textContent.includes(${JSON.stringify(title)})); button?.click(); return !!button; })()`);
      if (!selected) throw new Error(`Existing catalog entry missing: ${title}`);
      await click("运行只读调查");
      await wait(`${text}.includes(${JSON.stringify(expected)})`, "collector output displayed");
      check(`real collector output renders in existing ${key} entry without password values`, await evaluate(`!${text}.includes('fixture-private-password-4729') && ${text}.includes(${JSON.stringify(expected)}) && ${scope}.querySelector('.emergency-command-output .is-abnormal') !== null`));
      await click("关注与缺口");
      check(`focused ${key} output retains findings and collection scope`, await evaluate(`${scope}.querySelector('.emergency-command-output').textContent.includes(${JSON.stringify(expected)}) && ${scope}.querySelector('.emergency-command-output').textContent.includes('# 范围：')`));
      await screenshot(`04-${key}-observations`);
    }
  }
  await render(null);
  check("disconnection clears output and gives the original connection guidance", await evaluate(`${text}.includes('连接 SSH 目标后') && !${scope}.querySelector('.emergency-command-result')`));
  await evaluate("window.commandFixture.unmount(); true");
  check("no runtime, console or log errors during observation", report.errors.length === 0, report.errors);
} catch (error) {
  report.failure = String(error.stack ?? error); console.error(report.failure);
  if (session) {
    report.failureState = await session.evaluate("({text:document.querySelector('#command-workbench-fixture')?.textContent,calls:window.commandFixture?.calls})").catch(() => null);
    await session.screenshot(path.join(evidence, "failure.png")).catch(() => {});
  }
} finally {
  if (session) { try { await session.evaluate("document.querySelector('[data-testid=window-close]').click(); true"); } catch {} session.close(); }
  await waitFor(() => exited, { timeoutMs: 10000, label: "owned debug process exit" }).catch(() => {});
  if (!exited) child.kill();
  fs.writeFileSync(path.join(evidence, "report.json"), JSON.stringify(report, null, 2));
  fs.writeFileSync(path.join(evidence, "desktop.log"), output.join(""));
  console.log(`Evidence: ${evidence}`);
}
process.exitCode = report.failure || report.errors.length || report.checks.some(item => !item.passed) ? 1 : 0;
