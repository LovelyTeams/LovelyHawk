// The settings panel in the real window: open and close with focus returned,
// an unsaved draft discarded on cancel, out-of-range values refused, every
// group saved and applied (theme, interface, logging, terminal, connection,
// notifications, AI service with proxy), a write-only API key that the page
// never shows again and the data folder never holds in plain text, a dangerous
// key removal behind its own confirmation, and persistence across a restart.
// Two launches against one throwaway data root; no network, no target.

import { randomUUID } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { attach, delay, launchDesktop, waitFor } from "./cdp.mjs";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const executable = path.join(repositoryRoot, "target", "debug", process.platform === "win32" ? "lovelyhawk.exe" : "lovelyhawk");
const runRoot = path.join(repositoryRoot, "target", "desktop-debug", `settings-${randomUUID()}`);
const evidence = path.join(runRoot, "evidence");
const apiKey = `sk-probe-${randomUUID()}`;
const checks = [];
function check(name, ok, detail = null) {
  checks.push({ name, ok: Boolean(ok), detail });
  console.log(`${ok ? "PASS" : "FAIL"} ${name}${detail === null ? "" : ` — ${JSON.stringify(detail)}`}`);
}
fs.mkdirSync(evidence, { recursive: true });

async function run(phase, scenario) {
  const port = 11_200 + Math.floor(Math.random() * 80);
  const { child, output } = launchDesktop({ executable, archiveRoot: runRoot, port });
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
    await waitFor(() => session.evaluate("document.querySelector('[data-testid=\"open-settings\"]') !== null"), { label: "the title bar" });
    await scenario(session);
    check(`${phase}: the page never holds the API key`, !(await session.evaluate("document.documentElement.outerHTML")).includes(apiKey));
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

const field = (label) => `[...document.querySelectorAll('.settings-panel .settings-field')].find((candidate) => candidate.querySelector('span')?.textContent === ${JSON.stringify(label)})?.querySelector('input, select')`;
const setField = (label, value) => `(() => {
  const element = ${field(label)};
  if (!element) return false;
  const prototype = element instanceof HTMLSelectElement ? HTMLSelectElement.prototype : HTMLInputElement.prototype;
  Object.getOwnPropertyDescriptor(prototype, 'value').set.call(element, ${JSON.stringify(String(value))});
  element.dispatchEvent(new Event(element instanceof HTMLSelectElement ? 'change' : 'input', { bubbles: true }));
  return true;
})()`;
// Parenthesised: `a ?? null !== null` would parse as `a ?? (null !== null)`.
const fieldValue = (label) => `((${field(label)})?.value ?? null)`;
const toggle = (label, wanted) => `(() => {
  const box = [...document.querySelectorAll('.settings-panel .settings-toggle')].find((candidate) => candidate.textContent.includes(${JSON.stringify(label)}))?.querySelector('input');
  if (!box) return false;
  if (box.checked !== ${wanted}) box.click();
  return true;
})()`;
const tab = (label) => `(() => { const button = [...document.querySelectorAll('.settings-tabs [role="tab"]')].find((candidate) => candidate.textContent.trim() === ${JSON.stringify(label)}); if (!button) return false; button.click(); return true; })()`;
const clickText = (selector, text) => `(() => {
  const element = [...document.querySelectorAll(${JSON.stringify(selector)})].find((candidate) => candidate.textContent.trim() === ${JSON.stringify(text)});
  if (!element || element.disabled) return false;
  element.click();
  return true;
})()`;
const notice = "document.querySelector('.settings-footer [aria-live] p')?.textContent ?? null";
async function openSettings(session) {
  await session.evaluate("document.querySelector('[data-testid=\"open-settings\"]').focus(), document.querySelector('[data-testid=\"open-settings\"]').click(), true");
  await waitFor(() => session.evaluate(`${fieldValue("主题")} !== null`), { timeoutMs: 10_000, label: "the settings fields" });
}
async function escape(session) {
  await session.send("Input.dispatchKeyEvent", { type: "keyDown", key: "Escape", code: "Escape", windowsVirtualKeyCode: 27 });
  await session.send("Input.dispatchKeyEvent", { type: "keyUp", key: "Escape", code: "Escape", windowsVirtualKeyCode: 27 });
  await delay(400);
}

let originalTheme = null;
await run("first launch", async (session) => {
  await openSettings(session);
  const opened = await session.evaluate("({ dialog: document.querySelector('.settings-panel')?.getAttribute('role'), focusInside: document.querySelector('.settings-panel')?.contains(document.activeElement) ?? false })");
  check("settings opens as a dialog and takes focus", opened.dialog === "dialog" && opened.focusInside, opened);
  originalTheme = await session.evaluate(fieldValue("主题"));
  const startTheme = await session.evaluate("document.documentElement.dataset.theme");

  // A change that is not saved leaves nothing behind.
  await session.evaluate(setField("主题", originalTheme === "dark" ? "light" : "dark"));
  await session.evaluate(setField("侧栏宽度（px）", 333));
  await escape(session);
  const asked = await waitFor(() => session.evaluate("document.querySelector('.dialog-host h2')?.textContent ?? null"), { timeoutMs: 5_000, label: "the discard question" }).catch(() => null);
  await session.evaluate(clickText(".dialog-host button", "放弃更改"));
  await waitFor(() => session.evaluate("document.querySelector('.settings-panel') === null"), { timeoutMs: 5_000, label: "settings to close" });
  const focusBack = await session.evaluate("document.activeElement?.dataset.testid ?? null");
  check("closing with unsaved changes asks, then returns focus to the 设置 button", asked === "放弃未保存的更改" && focusBack === "open-settings", { asked, focusBack });
  await openSettings(session);
  const reopened = { theme: await session.evaluate(fieldValue("主题")), width: await session.evaluate(fieldValue("侧栏宽度（px）")), applied: await session.evaluate("document.documentElement.dataset.theme") };
  check("a discarded draft changed nothing", reopened.theme === originalTheme && reopened.width !== "333" && reopened.applied === startTheme, reopened);

  // Out-of-range values are refused, not clamped silently or saved.
  await session.evaluate(tab("连接"));
  await waitFor(() => session.evaluate(`${fieldValue("默认 SSH 端口")} !== null`), { timeoutMs: 5_000, label: "the connection tab" });
  await session.evaluate(setField("默认 SSH 端口", 70000));
  await session.evaluate(clickText(".settings-panel button", "保存设置"));
  const refused = await waitFor(() => session.evaluate(notice), { timeoutMs: 5_000, label: "the refusal" }).catch(() => null);
  check("an out-of-range port is refused before saving", refused === "请修正越界或无效的设置值后再保存。", refused);
  await session.evaluate(setField("默认 SSH 端口", 2222));
  await session.evaluate(setField("保活间隔（秒）", 45));

  // Every group, then save once.
  await session.evaluate(tab("通用"));
  await waitFor(() => session.evaluate(`${fieldValue("主题")} !== null`), { timeoutMs: 5_000, label: "the general tab" });
  await session.evaluate(setField("主题", "dark"));
  await session.evaluate(setField("侧栏宽度（px）", 300));
  await session.evaluate(setField("诊断日志级别", "debug"));
  await session.evaluate(toggle("紧凑模式", true));
  await session.evaluate(toggle("命令完成通知", false));
  await session.evaluate(tab("终端"));
  await waitFor(() => session.evaluate(`${fieldValue("字号（px）")} !== null`), { timeoutMs: 5_000, label: "the terminal tab" });
  await session.evaluate(setField("字号（px）", 16));
  await session.evaluate(tab("AI"));
  await waitFor(() => session.evaluate(clickText(".settings-panel button", "新增服务商")), { timeoutMs: 5_000, label: "新增服务商" });
  await waitFor(() => session.evaluate(`${fieldValue("显示名称")} !== null`), { timeoutMs: 5_000, label: "the new provider" });
  await session.evaluate(setField("显示名称", "实验服务商"));
  await session.evaluate(setField("接口地址", "https://ai.example.test/v1"));
  await session.evaluate(setField("模型", "probe-model"));
  await session.evaluate(toggle("启用代理", true));
  await waitFor(() => session.evaluate(`${fieldValue("代理 URL")} !== null`), { timeoutMs: 5_000, label: "the proxy fields" });
  await session.evaluate(setField("代理 URL", "http://127.0.0.1:8080"));
  await session.evaluate(clickText(".settings-panel button", "保存设置"));
  const saved = await waitFor(() => session.evaluate(`(() => { const text = ${notice}; return text === '设置已保存到程序目录下的 data 文件夹。' ? text : null; })()`), { timeoutMs: 10_000, label: "the save" }).catch(() => session.evaluate(notice));
  const applied = await session.evaluate("({ theme: document.documentElement.dataset.theme, width: getComputedStyle(document.documentElement).getPropertyValue('--sidebar-width').trim(), density: document.documentElement.dataset.density ?? null })");
  check("saving says where it went and applies theme, sidebar width and density at once", saved === "设置已保存到程序目录下的 data 文件夹。" && applied.theme === "dark" && applied.width === "300px" && applied.density === "compact", { saved, applied });

  // The API key is write-only: set, never shown, cleared only with confirmation.
  await waitFor(() => session.evaluate("document.querySelector('[data-testid=\"settings-api-key-input\"]')?.disabled === false"), { timeoutMs: 5_000, label: "the key input" });
  await session.evaluate(`(() => {
    const input = document.querySelector('[data-testid="settings-api-key-input"]');
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(input, ${JSON.stringify(apiKey)});
    input.dispatchEvent(new Event('input', { bubbles: true }));
    return true;
  })()`);
  await session.evaluate("document.querySelector('[data-testid=\"settings-api-key-replace\"]').click(), true");
  const keyState = await waitFor(() => session.evaluate("(() => { const state = document.querySelector('[aria-label=\"API Key 状态\"] strong')?.textContent; return state === '已加密保存' ? { state, input: document.querySelector('[data-testid=\"settings-api-key-input\"]').value, type: document.querySelector('[data-testid=\"settings-api-key-input\"]').type } : null; })()"), { timeoutMs: 10_000, label: "the stored key" }).catch(() => null);
  check("an API key is stored encrypted and the field empties", keyState?.state === "已加密保存" && keyState.input === "" && keyState.type === "password", keyState);
  const dataFiles = fs.readdirSync(path.join(runRoot, "data"), { recursive: true }).filter((name) => typeof name === "string" && !name.startsWith("webview2"));
  const leaked = dataFiles.filter((name) => { try { return fs.statSync(path.join(runRoot, "data", name)).isFile() && fs.readFileSync(path.join(runRoot, "data", name), "latin1").includes(apiKey); } catch { return false; } });
  check("no file in the data folder holds the key in plain text", leaked.length === 0, leaked);

  await session.evaluate("document.querySelector('[data-testid=\"settings-api-key-clear\"]').click(), true");
  const confirmation = await waitFor(() => session.evaluate("(() => { const dialog = [...document.querySelectorAll('.settings-panel [role=\"alertdialog\"], .settings-mutation-dialog, [role=\"alertdialog\"]')].find((candidate) => candidate.textContent.includes('API Key')); return dialog ? dialog.textContent.slice(0, 200) : null; })()"), { timeoutMs: 8_000, label: "the clear confirmation" }).catch(() => null);
  check("clearing the key asks for a separate confirmation", typeof confirmation === "string" && confirmation.includes("永久清除 API Key"), confirmation);
  await session.screenshot(path.join(evidence, "settings-clear-key.png"));
  const confirmed = await session.evaluate(`(() => { const button = [...document.querySelectorAll('[role="alertdialog"] button')].find((candidate) => /确认/u.test(candidate.textContent)); if (!button) return false; button.click(); return true; })()`);
  const cleared = await waitFor(() => session.evaluate("document.querySelector('[aria-label=\"API Key 状态\"] strong')?.textContent === '未配置'"), { timeoutMs: 10_000, label: "the cleared key" }).catch(() => false);
  check("after confirming, the key is gone", confirmed && cleared);
  // Store it again so the restart can show it survived.
  await session.evaluate(`(() => {
    const input = document.querySelector('[data-testid="settings-api-key-input"]');
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(input, ${JSON.stringify(apiKey)});
    input.dispatchEvent(new Event('input', { bubbles: true }));
    return true;
  })()`);
  await session.evaluate("document.querySelector('[data-testid=\"settings-api-key-replace\"]').click(), true");
  await waitFor(() => session.evaluate("document.querySelector('[aria-label=\"API Key 状态\"] strong')?.textContent === '已加密保存'"), { timeoutMs: 10_000, label: "the stored key again" });

  await escape(session);
  const closed = await waitFor(() => session.evaluate("document.querySelector('.settings-panel') === null ? document.activeElement?.dataset.testid ?? '' : null"), { timeoutMs: 5_000, label: "settings to close" }).catch(() => null);
  check("Escape closes saved settings without asking and returns focus", closed === "open-settings", closed);
});

await run("after restart", async (session) => {
  const applied = await session.evaluate("({ theme: document.documentElement.dataset.theme, width: getComputedStyle(document.documentElement).getPropertyValue('--sidebar-width').trim(), density: document.documentElement.dataset.density ?? null })");
  check("theme, sidebar width and density are applied at startup", applied.theme === "dark" && applied.width === "300px" && applied.density === "compact", applied);
  await openSettings(session);
  const general = { log: await session.evaluate(fieldValue("诊断日志级别")), commandToast: await session.evaluate("[...document.querySelectorAll('.settings-panel .settings-toggle')].find((label) => label.textContent.includes('命令完成通知'))?.querySelector('input').checked ?? null") };
  await session.evaluate(tab("连接"));
  await waitFor(() => session.evaluate(`${fieldValue("默认 SSH 端口")} !== null`), { timeoutMs: 5_000, label: "the connection tab" });
  const connection = { port: await session.evaluate(fieldValue("默认 SSH 端口")), keepalive: await session.evaluate(fieldValue("保活间隔（秒）")) };
  await session.evaluate(tab("终端"));
  await waitFor(() => session.evaluate(`${fieldValue("字号（px）")} !== null`), { timeoutMs: 5_000, label: "the terminal tab" });
  const terminal = await session.evaluate(fieldValue("字号（px）"));
  await session.evaluate(tab("AI"));
  await waitFor(() => session.evaluate(`${fieldValue("显示名称")} !== null`), { timeoutMs: 5_000, label: "the provider" });
  const ai = { label: await session.evaluate(fieldValue("显示名称")), endpoint: await session.evaluate(fieldValue("接口地址")), proxy: await session.evaluate(fieldValue("代理 URL")), key: await session.evaluate("document.querySelector('[aria-label=\"API Key 状态\"] strong')?.textContent ?? null") };
  check("every saved value came back after a restart", general.log === "debug" && general.commandToast === false && connection.port === "2222" && connection.keepalive === "45" && terminal === "16" &&
    ai.label === "实验服务商" && ai.endpoint === "https://ai.example.test/v1" && ai.proxy === "http://127.0.0.1:8080" && ai.key === "已加密保存", { general, connection, terminal, ai });
  await session.screenshot(path.join(evidence, "settings-after-restart.png"));
  await escape(session);
});

const failed = checks.filter((entry) => !entry.ok);
fs.writeFileSync(path.join(evidence, "report.json"), `${JSON.stringify({
  schema: "lovelyhawk-settings-probe/v1",
  status: failed.length === 0 ? "PASS" : "FAIL",
  generatedAt: new Date().toISOString(),
  checks,
}, null, 2)}\n`);
console.log(`${failed.length === 0 ? "PASS" : "FAIL"}: ${checks.length - failed.length}/${checks.length}; evidence in ${evidence}`);
process.exitCode = failed.length === 0 ? 0 : 1;
