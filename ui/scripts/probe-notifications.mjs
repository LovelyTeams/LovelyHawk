// Toast notifications in the real window: saving settings raises one that is
// held back (hidden and inert) while a modal is open, shows once it closes,
// announces itself politely, sits above the page, expires after its three
// seconds, can be dismissed by hand, and a repeated event renews one toast
// instead of stacking two. No target is involved; throwaway data root, with
// the debug clipboard hook so copying the log leaves the system clipboard alone.

import { randomUUID } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { attach, delay, launchDesktop, waitFor } from "./cdp.mjs";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const executable = path.join(repositoryRoot, "target", "debug", process.platform === "win32" ? "lovelyhawk.exe" : "lovelyhawk");
const runRoot = path.join(repositoryRoot, "target", "desktop-debug", `notifications-${randomUUID()}`);
const evidence = path.join(runRoot, "evidence");
const checks = [];
function check(name, ok, detail = null) {
  checks.push({ name, ok: Boolean(ok), detail });
  console.log(`${ok ? "PASS" : "FAIL"} ${name}${detail === null ? "" : ` — ${JSON.stringify(detail)}`}`);
}
fs.mkdirSync(evidence, { recursive: true });

const port = 11_000 + Math.floor(Math.random() * 80);
const { child, output } = launchDesktop({
  executable,
  archiveRoot: runRoot,
  port,
  extraEnv: { LOVELYHAWK_TEST_CLIPBOARD_FILE: path.join(runRoot, "clipboard.txt") },
});
let exitCode = null;
child.once("exit", (code) => { exitCode = code; });
const errors = [];

const toasts = `(() => {
  const layer = document.querySelector('.notification-overlay-layer');
  const cards = [...document.querySelectorAll('.notification-card')];
  return {
    blocked: layer?.classList.contains('is-modal-blocked') ?? null,
    inert: layer?.inert ?? null,
    visibility: layer ? getComputedStyle(layer).visibility : null,
    zIndex: layer ? Number(getComputedStyle(layer).zIndex) : null,
    live: document.querySelector('.notification-stack')?.getAttribute('aria-live') ?? null,
    cards: cards.map((card) => ({ role: card.getAttribute('role'), text: card.querySelector('p')?.textContent ?? '', markup: card.querySelector('p')?.children.length ?? 0 })),
  };
})()`;
const clickText = (selector, text) => `(() => {
  const element = [...document.querySelectorAll(${JSON.stringify(selector)})].find((candidate) => candidate.textContent.trim() === ${JSON.stringify(text)});
  if (!element || element.disabled) return false;
  element.click();
  return true;
})()`;
async function escape(session) {
  await session.send("Input.dispatchKeyEvent", { type: "keyDown", key: "Escape", code: "Escape", windowsVirtualKeyCode: 27 });
  await session.send("Input.dispatchKeyEvent", { type: "keyUp", key: "Escape", code: "Escape", windowsVirtualKeyCode: 27 });
}
async function saveCompactToggle(session) {
  await session.evaluate("document.querySelector('[data-testid=\"open-settings\"]').click(), true");
  await waitFor(() => session.evaluate(`(() => {
    const toggle = [...document.querySelectorAll('.settings-panel .settings-toggle')].find((label) => label.textContent.includes('紧凑模式'));
    if (!toggle) return false;
    toggle.querySelector('input').click();
    return true;
  })()`), { timeoutMs: 10_000, label: "the compact toggle" });
  await waitFor(() => session.evaluate(clickText(".settings-panel button", "保存设置")), { timeoutMs: 10_000, label: "保存设置" });
  return waitFor(() => session.evaluate(`(() => { const t = ${toasts}; return t.cards.length > 0 ? t : null; })()`), { timeoutMs: 10_000, label: "the settings toast" }).catch(() => null);
}

try {
  const { session } = await attach(port, (url) => /^https?:\/\/tauri\.localhost\/(index\.html)?$/u.test(url));
  session.onEvent((method, params) => {
    if (method === "Runtime.exceptionThrown" || (method === "Runtime.consoleAPICalled" && params?.type === "error") || (method === "Log.entryAdded" && params?.entry?.level === "error")) {
      errors.push(JSON.stringify(params).slice(0, 1_500));
    }
  });
  await session.send("Runtime.enable");
  await session.send("Log.enable");
  fs.writeFileSync(path.join(evidence,"observation.json"),JSON.stringify({observedAt:new Date().toISOString(),origin:"https://tauri.localhost"}));
  await waitFor(() => session.evaluate("document.querySelector('[data-testid=\"open-settings\"]') !== null"), { label: "the title bar" });

  let now = await saveCompactToggle(session);
  check("saving settings raises a toast that waits behind the open panel", now?.cards[0]?.text === "设置已安全保存。" && now.blocked === true && now.inert === true && now.visibility === "hidden", now);
  await escape(session);
  now = await waitFor(() => session.evaluate(`(() => { const t = ${toasts}; return t.blocked === false ? t : null; })()`), { timeoutMs: 5_000, label: "the panel to close" }).catch(() => null);
  check("once the panel closes the toast shows, above the page, announced politely", now?.cards.length === 1 && now.visibility === "visible" && now.inert === false && now.zIndex >= 1_400 && now.live === "polite" && now.cards[0].role === "status", now);
  check("the toast text is plain", now?.cards.every((card) => card.markup === 0));
  await session.screenshot(path.join(evidence, "settings-saved-toast.png"));
  const gone = await waitFor(() => session.evaluate(`${toasts}.cards.length === 0`), { timeoutMs: 6_000, label: "the toast to expire" }).catch(() => false);
  check("an information toast expires on its own after about three seconds", gone);

  now = await saveCompactToggle(session);
  await escape(session);
  await waitFor(() => session.evaluate(`${toasts}.blocked === false`), { timeoutMs: 5_000, label: "the panel to close again" });
  const dismissed = await session.evaluate(`(() => {
    const button = document.querySelector('.notification-dismiss');
    if (!button) return null;
    const label = button.getAttribute('aria-label');
    button.click();
    return label;
  })()`);
  await delay(300);
  check("a toast can be dismissed by its labelled button", dismissed === "关闭成功通知" && (await session.evaluate(toasts)).cards.length === 0, dismissed);

  // Copying the log twice inside the toast's lifetime renews one toast.
  const opener = await session.evaluate("document.querySelector('[data-testid=\"open-application-log\"]') ? 'open-application-log' : 'sidebar-open-application-log'");
  await session.evaluate(`document.querySelector('[data-testid="${opener}"]').click(), true`);
  await waitFor(() => session.evaluate("document.querySelector('[aria-labelledby=\"application-log-title\"]') !== null"), { timeoutMs: 10_000, label: "the log overlay" });
  for (let round = 0; round < 2; round += 1) {
    await waitFor(() => session.evaluate(clickText(".application-log-actions button", "复制筛选结果")), { timeoutMs: 10_000, label: "复制筛选结果" });
    await waitFor(() => session.evaluate("document.querySelector('.notification-stack .notification-card p')?.textContent === '已复制脱敏后的应用日志。'"), { timeoutMs: 10_000, label: "the copy" });
    await delay(200);
  }
  now = await session.evaluate(toasts);
  check("a repeated event renews one toast instead of stacking two", now.cards.length === 1 && now.cards[0].text === "已复制脱敏后的应用日志。" && now.blocked === true, now.cards);
  await escape(session);
  now = await waitFor(() => session.evaluate(`(() => { const t = ${toasts}; return t.blocked === false ? t : null; })()`), { timeoutMs: 5_000, label: "the overlay to close" }).catch(() => null);
  check("after the overlay closes the renewed toast is the only one shown", now?.cards.length === 1, now?.cards);

  await waitFor(()=>session.evaluate(`${toasts}.cards.length === 0`),{timeoutMs:6000,label:"toast expiry before history"});
  await session.evaluate("(()=>{const b=document.querySelector('[data-testid=\"open-notifications\"]'); b.focus(); b.click(); return true;})()");
  await waitFor(()=>session.evaluate("document.querySelector('.notification-center') !== null"),{label:"notification center"});
  check("expired toasts remain in global history and opening marks them read",await session.evaluate("document.querySelector('.notification-center').textContent.includes('设置已安全保存') && document.querySelector('.notification-center').textContent.includes('已复制脱敏后的应用日志') && !document.querySelector('.notification-count')"));
  check("notification entry is the leftmost status item",await session.evaluate("document.querySelector('.window-statusbar .statusbar-group').firstElementChild.dataset.testid === 'open-notifications'"));
  check("center traps focus and the workspace is inert",await session.evaluate("document.querySelector('.notification-center').contains(document.activeElement) && document.querySelector('.workspace').inert"));
  await session.screenshot(path.join(evidence,"notification-center.png"));
  await escape(session);
  check("Escape returns focus to notification entry",await session.evaluate("document.activeElement?.dataset.testid === 'open-notifications'"));
  // Actual Windows page + host clipboard stub, without a remote target.
  await session.evaluate("[...document.querySelectorAll('button')].find(b=>b.title==='切换至 Windows 应急响应工作台')?.click(),true");
  await waitFor(()=>session.evaluate("document.querySelector('button[aria-label=\"远程桌面\"]') !== null"),{label:"Windows sidebar"});
  await session.evaluate("document.querySelector('button[aria-label=\"远程桌面\"]').click(),true");
  await waitFor(()=>session.evaluate(clickText(".wir-desktop header button","复制免落地 PowerShell")),{label:"fileless copy"});
  await waitFor(()=>session.evaluate("document.querySelector('.notification-stack p')?.textContent==='已复制到剪贴板。'"),{label:"global Windows copy toast"});
  check("Windows operation feedback no longer occupies a page banner",await session.evaluate("![...document.querySelectorAll('.win-ir-notice')].some(n=>n.textContent.includes('已复制到剪贴板'))"));
  check("sidebar toast is small and on the left",await session.evaluate("(()=>{const r=document.querySelector('.notification-stack').getBoundingClientRect();return r.left<32 && r.width<=390 && r.height<200;})()"));
  await session.screenshot(path.join(evidence,"windows-copy-toast.png"));
  await waitFor(()=>session.evaluate(`${toasts}.cards.length === 0`),{timeoutMs:6000,label:"Windows toast expiry"});
  await session.evaluate("document.querySelector('[data-testid=\"open-settings\"]').click(), true");
  await waitFor(()=>session.evaluate(`(() => {
    const toggle=[...document.querySelectorAll('.settings-toggle')].find(label=>label.textContent.includes('显示状态栏'));
    if (!toggle) return false;
    toggle.querySelector('input').click(); return true;
  })()`),{label:"status bar preference"});
  await waitFor(()=>session.evaluate(clickText(".settings-panel button","保存设置")),{label:"saving hidden status bar"});
  await waitFor(()=>session.evaluate("document.querySelector('.notification-stack p')?.textContent==='设置已安全保存。'"),{label:"hidden status bar saved"});
  await escape(session);
  await waitFor(()=>session.evaluate("!document.querySelector('.settings-panel')"),{label:"settings closed"});
  check("hidden status bar keeps a reachable notification entry in the sidebar",await session.evaluate("!document.querySelector('.window-statusbar') && document.querySelector('.sidebar-footer [data-testid=\"open-notifications\"]')?.getClientRects().length>0"));
  await session.send("Emulation.setDeviceMetricsOverride",{width:640,height:640,deviceScaleFactor:1,mobile:false});
  await session.evaluate("document.querySelector('[data-testid=\"open-notifications\"]').click(),true");
  await waitFor(()=>session.evaluate("document.querySelector('.notification-center') !== null"),{label:"narrow notification center"});
  check("notification history fits a narrow window",await session.evaluate("(()=>{const r=document.querySelector('.notification-center').getBoundingClientRect();return r.left>=0 && r.right<=innerWidth && r.top>=0 && r.bottom<=innerHeight;})()"));
  await session.screenshot(path.join(evidence,"notification-center-narrow.png"));
  await escape(session);
  check("no console errors", errors.length === 0, errors.slice(0, 3));
  await session.evaluate("document.querySelector('[data-testid=\"window-close\"]').click(), true");
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
  schema: "lovelyhawk-notifications-probe/v1",
  status: failed.length === 0 ? "PASS" : "FAIL",
  generatedAt: new Date().toISOString(),
  checks,
}, null, 2)}\n`);
console.log(`${failed.length === 0 ? "PASS" : "FAIL"}: ${checks.length - failed.length}/${checks.length}; evidence in ${evidence}`);
process.exitCode = failed.length === 0 ? 0 : 1;
