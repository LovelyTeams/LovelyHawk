// Host keys and connection failures in the Tauri window, against real lab
// hosts, without touching any host's keys or configuration: a connection
// imported with a stale pinned fingerprint is refused and keeps its pin; a
// first connection asks for the key with focus on 取消尝试 (Enter does not
// trust it), declining pins nothing and leaves no session, and trusting pins
// exactly the key the host really has; a wrong password, a closed port and a
// name that cannot resolve each say which kind of failure it was, in Chinese.
//
//   node ui/scripts/probe-host-key.mjs

import { execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { labTarget } from "../../tools/lab/lab-target.mjs";
import { attach, delay, launchDesktop, waitFor } from "./cdp.mjs";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const executable = path.join(repositoryRoot, "target", "debug", process.platform === "win32" ? "lovelyhawk.exe" : "lovelyhawk");
const runRoot = path.join(repositoryRoot, "target", "desktop-debug", `host-key-${randomUUID()}`);
const evidence = path.join(runRoot, "evidence");
const answersFile = path.join(runRoot, "dialog-answers.json");
const exportFile = path.join(runRoot, "files", "connections.json");
const checks = [];
function check(name, ok, detail = null) {
  checks.push({ name, ok: Boolean(ok), detail });
  console.log(`${ok ? "PASS" : "FAIL"} ${name}${detail === null ? "" : ` — ${JSON.stringify(detail).slice(0, 400)}`}`);
}
fs.mkdirSync(evidence, { recursive: true });
fs.mkdirSync(path.dirname(exportFile), { recursive: true });
fs.writeFileSync(answersFile, JSON.stringify([exportFile]));

const stale = { lab: labTarget("ubuntu"), name: "旧指纹 ubuntu" };
const fresh = { lab: labTarget("debian"), name: "首次 debian", container: "lab-debian" };
// A well-formed SHA-256 fingerprint that is not this host's.
const stalePin = `SHA256:${"A".repeat(43)}`;
const entry = ({ lab, name }, hostKey) => ({
  name, host: lab.host, port: lab.port, username: lab.username, auth_method: "password",
  private_key_path: null, certificate_path: null, agent_identity_fingerprint: null, jump_host: null,
  tags: [], notes: null, environment: null, role: null, group: null, host_key_fingerprint: hostKey,
});
// Three ways a connection fails that need different next steps. None touches a
// host's configuration: one wrong password, a port nothing listens on, and a
// name under .invalid, which is reserved never to resolve.
const failures = [
  { name: "错误口令 alma", lab: labTarget("alma"), password: `wrong-${randomUUID().slice(0, 8)}`,
    code: "认证没有通过" },
  { name: "关闭的端口", lab: { ...labTarget("ubuntu"), port: 2299 }, password: "unused", code: "没能和这台主机建立 SSH 连接" },
  { name: "不存在的主机名", lab: { ...labTarget("ubuntu"), host: "no-such-host.invalid" }, password: "unused",
    code: "找不到这个主机名" },
];
fs.writeFileSync(exportFile, JSON.stringify({
  format: "lovelyres-connections",
  schema_version: 1,
  exported_at: new Date().toISOString(),
  connections: [entry(stale, stalePin), entry(fresh, null), ...failures.map((failure) => entry(failure, null))],
}, null, 2));

/** The fingerprints of every host key the host offers, read on the host itself. */
function hostFingerprints(container) {
  const output = execFileSync("wsl.exe", ["-d", "Ubuntu", "-u", "root", "-e", "docker", "exec", container, "sh", "-c",
    "for key in /etc/ssh/ssh_host_*_key.pub; do ssh-keygen -lf \"$key\"; done"], { encoding: "utf8" });
  return [...output.matchAll(/SHA256:[A-Za-z0-9+/]{43}/gu)].map((match) => match[0]);
}

const port = 11_900 + Math.floor(Math.random() * 80);
const { child, output } = launchDesktop({ executable, archiveRoot: runRoot, port, extraEnv: { LOVELYHAWK_TEST_DIALOG_ANSWERS: answersFile } });
let exitCode = null;
child.once("exit", (code) => { exitCode = code; });
const errors = [];
const clickText = (selector, text) => `(() => { const element = [...document.querySelectorAll(${JSON.stringify(selector)})].find((candidate) => candidate.textContent.trim() === ${JSON.stringify(text)}); if (!element || element.disabled) return false; element.click(); return true; })()`;
const field = (label) => `[...document.querySelectorAll('.connection-editor .connection-field')].find((candidate) => candidate.querySelector('span')?.textContent.startsWith(${JSON.stringify(label)}))`;
const setField = (label, value) => `(() => {
  const input = ${field(label)}?.querySelector('input, textarea');
  if (!input) return false;
  Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(input, ${JSON.stringify(value)});
  input.dispatchEvent(new Event('input', { bubbles: true }));
  return true;
})()`;
const state = `({
  notice: document.querySelector('.connection-notice:not(.error)')?.textContent ?? null,
  error: document.querySelector('.connection-notice.error')?.textContent ?? null,
  editor: document.querySelector('.connection-editor') !== null,
  detail: document.querySelector('.connection-details-view h2')?.textContent ?? null,
  sections: [...document.querySelectorAll('.connection-detail-section')].map((section) => section.textContent),
  connected: document.querySelector('[data-testid="sidebar-disconnect-target"]') !== null,
  attempt: document.querySelector('.ssh-attempt-dialog')?.textContent ?? null,
})`;

try {
  const { session: main } = await attach(port, (url) => /^https?:\/\/tauri\.localhost\/(index\.html)?$/u.test(url));
  main.onEvent((method, params) => {
    if (method === "Runtime.exceptionThrown" || (method === "Runtime.consoleAPICalled" && params?.type === "error")) errors.push(JSON.stringify(params).slice(0, 1_500));
  });
  await main.send("Runtime.enable");
  const now = () => main.evaluate(state);
  const until = (predicate, label, timeoutMs = 15_000) => waitFor(async () => {
    const value = await now();
    return predicate(value) ? value : null;
  }, { timeoutMs, label });
  async function select(name) {
    await waitFor(() => main.evaluate(`(() => { const row = [...document.querySelectorAll('.connection-list .connection-list-row')].find((candidate) => candidate.querySelector('strong')?.textContent === ${JSON.stringify(name)}); if (!row || row.disabled) return false; row.click(); return true; })()`), { label: `the ${name} row` });
    return until((value) => value.detail === name, `${name} selected`);
  }
  async function setPassword(name, password) {
    await select(name);
    await waitFor(() => main.evaluate(clickText(".connection-details-view footer button", "编辑配置")), { label: "编辑配置" });
    await waitFor(() => main.evaluate("document.querySelector('.connection-editor') !== null"), { label: "the editor" });
    await main.evaluate(setField("SSH 密码", password));
    await main.evaluate("document.querySelector('.connection-editor button[type=\"submit\"]').click(), true");
    return until((value) => !value.editor && value.detail === name, `saving ${name}`);
  }
  async function openManager() {
    await waitFor(() => main.evaluate("(() => { const button = document.querySelector('[data-testid=\"sidebar-connect-target\"]'); if (!button) return false; button.click(); return true; })()"), { label: "连接管理" });
    await waitFor(() => main.evaluate("document.querySelector('.connection-manager') !== null"), { label: "the connection manager" });
  }
  const pinOf = (value) => value.sections.join(" ").match(/SHA256:[A-Za-z0-9+/]{43}/u)?.[0] ?? null;

  await openManager();
  await waitFor(() => main.evaluate("document.querySelector('[data-testid=\"connection-import\"]') !== null"), { label: "导入" });
  await main.evaluate("document.querySelector('[data-testid=\"connection-import\"]').click(), true");
  const imported = await until((value) => value.notice?.startsWith("连接导入完成") === true, "the import");
  check("all connections are imported, one carrying a pinned fingerprint", imported.notice === "连接导入完成：导入 5，跳过已有 0，跳过文件内重复 0。", imported.notice);
  await setPassword(stale.name, stale.lab.password);
  await setPassword(fresh.name, fresh.lab.password);
  for (const failure of failures) await setPassword(failure.name, failure.password);
  const stored = await select(stale.name);
  check("the imported pin is kept through an edit of the password", pinOf(stored) === stalePin, pinOf(stored));

  // 1. A pinned fingerprint that is not the host's: refused, nothing replaced.
  check("the stale pin really is not one of the host's keys", !hostFingerprints("lab-ubuntu").includes(stalePin));
  await waitFor(() => main.evaluate(clickText(".connection-details-view header button", "连接目标")), { label: "连接目标" });
  const refused = await waitFor(() => main.evaluate("document.querySelector('.ssh-failure-panel h3')?.textContent ?? null"), { timeoutMs: 60_000, label: "the refusal" }).catch(() => null);
  const refusedText = await main.evaluate("document.querySelector('.ssh-attempt-dialog')?.textContent ?? ''");
  check("a changed host key is refused and says it will not be accepted automatically",
    refused === "主机密钥已变化，连接被拒绝" && refusedText.includes("不会自动接受新的主机密钥"), refused);
  check("the refusal offers no way to trust the new key", await main.evaluate("document.querySelector('[data-testid=\"ssh-host-key-trust\"]') === null"));
  await main.screenshot(path.join(evidence, "host-key-changed.png"));
  await main.evaluate(clickText(".ssh-attempt-dialog footer button", "关闭"));
  await waitFor(() => main.evaluate("document.querySelector('.ssh-attempt-dialog') === null"), { label: "the attempt to close" });
  let after = await select(stale.name);
  check("nothing connected and the old pin is still the one on record", !after.connected && pinOf(after) === stalePin, { connected: after.connected, pin: pinOf(after) });

  // 2. A first connection: asked, with focus away from trusting it.
  const real = hostFingerprints(fresh.container);
  after = await select(fresh.name);
  check("the new connection has no pin yet", pinOf(after) === null && after.sections.join(" ").includes("首次连接时需要独立核验指纹"), after.sections[0]?.slice(0, 120));
  await waitFor(() => main.evaluate(clickText(".connection-details-view header button", "连接目标")), { label: "连接目标 (first)" });
  const shown = await waitFor(() => main.evaluate("document.querySelector('.ssh-host-key-panel code')?.textContent ?? null"), { timeoutMs: 60_000, label: "the host-key prompt" });
  check("the prompt shows a fingerprint the host really has", real.includes(shown), { shown, real });
  const focused = await waitFor(() => main.evaluate("document.activeElement?.dataset?.testid ?? null"), { timeoutMs: 5_000, label: "initial focus" }).catch(() => null);
  check("focus starts on 取消尝试, not on trusting the key", focused === "ssh-attempt-cancel", focused);
  await main.screenshot(path.join(evidence, "host-key-prompt.png"));
  // Enter on the focused control cancels; it never trusts.
  await main.send("Input.dispatchKeyEvent", { type: "keyDown", key: "Enter", code: "Enter", windowsVirtualKeyCode: 13, text: "\r", unmodifiedText: "\r" });
  await main.send("Input.dispatchKeyEvent", { type: "keyUp", key: "Enter", code: "Enter", windowsVirtualKeyCode: 13 });
  const declined = await waitFor(() => main.evaluate("document.querySelector('.ssh-cancelled')?.textContent ?? (document.querySelector('.ssh-attempt-dialog') === null ? 'closed' : null)"), { timeoutMs: 15_000, label: "the declined attempt" }).catch(() => null);
  check("Enter declines the unverified key", declined !== null && !(await now()).connected, declined);
  if (await main.evaluate("document.querySelector('.ssh-attempt-dialog') !== null")) {
    await main.evaluate(clickText(".ssh-attempt-dialog footer button", "关闭"));
    await waitFor(() => main.evaluate("document.querySelector('.ssh-attempt-dialog') === null"), { label: "the attempt to close" });
  }
  after = await select(fresh.name);
  check("declining pins nothing and leaves no session", pinOf(after) === null && !after.connected, { pin: pinOf(after), connected: after.connected });

  // 3. Trusting it: connected, and exactly that key is pinned.
  await waitFor(() => main.evaluate(clickText(".connection-details-view header button", "连接目标")), { label: "连接目标 (again)" });
  const again = await waitFor(() => main.evaluate("document.querySelector('.ssh-host-key-panel code')?.textContent ?? null"), { timeoutMs: 60_000, label: "the prompt again" });
  await main.evaluate("document.querySelector('[data-testid=\"ssh-host-key-trust\"]').click(), true");
  const connected = await waitFor(() => main.evaluate("document.querySelector('[data-testid=\"sidebar-disconnect-target\"]') !== null && document.querySelector('.connection-manager-backdrop') === null"), { timeoutMs: 90_000, label: "the login" }).catch(() => false);
  check("trusting the verified key connects", connected === true);
  if (connected === true) {
    await main.evaluate("document.querySelector('[data-testid=\"sidebar-disconnect-target\"]').click(), true");
    await waitFor(() => main.evaluate("document.querySelector('[data-testid=\"sidebar-disconnect-target\"]') === null"), { timeoutMs: 20_000, label: "the disconnect" });
  }
  await openManager();
  after = await select(fresh.name);
  check("the pinned fingerprint is exactly the key that was shown and trusted", pinOf(after) === again && real.includes(again), { pinned: pinOf(after), shown: again });

  // 4. Failures say which kind they are, in plain words, with no host text.
  for (const failure of failures) {
    await select(failure.name);
    await waitFor(() => main.evaluate(clickText(".connection-details-view header button", "连接目标")), { label: `连接目标 (${failure.name})` });
    // A wrong password on a host this run has not pinned still asks for the key first.
    const outcome = await waitFor(async () => {
      if (await main.evaluate("document.querySelector('[data-testid=\"ssh-host-key-trust\"]') !== null")) {
        await main.evaluate("document.querySelector('[data-testid=\"ssh-host-key-trust\"]').click(), true");
        return null;
      }
      return main.evaluate("document.querySelector('.ssh-failure-panel') ? document.querySelector('.ssh-failure-panel').textContent : null");
    }, { timeoutMs: 90_000, label: `the ${failure.name} failure` }).catch(() => null);
    const banner = await main.evaluate("document.querySelector('.connection-notice.error')?.textContent ?? ''");
    check(`${failure.name}: the failure says which kind it is, in Chinese, and no English`,
      outcome !== null && outcome.includes(failure.code) && !/[A-Za-z]{5,}/u.test(outcome.replace(/SSH|DNS|Agent/gu, "")),
      { outcome: outcome?.slice(0, 160) });
    check(`${failure.name}: the connection manager's notice is in Chinese too`,
      banner === "" || (!/could not|failed|changed/iu.test(banner) && /[一-鿿]/u.test(banner)), banner.slice(0, 160));
    await main.evaluate(clickText(".ssh-attempt-dialog footer button", "关闭"));
    await waitFor(() => main.evaluate("document.querySelector('.ssh-attempt-dialog') === null"), { label: "the attempt to close" });
  }
  await main.screenshot(path.join(evidence, "connection-failures.png"));

  check("no console errors", errors.length === 0, errors.slice(0, 3));
  await main.evaluate("document.querySelector('[data-testid=\"window-close\"]').click(), true");
  await waitFor(() => exitCode !== null, { timeoutMs: 20_000, label: "exit" }).catch(() => undefined);
  check("the app exits cleanly", exitCode === 0, exitCode);
} catch (error) {
  check("probe completed", false, error instanceof Error ? error.message : String(error));
  console.error(output.join("").slice(-3_000));
} finally {
  if (exitCode === null) child.kill();
}

const failed = checks.filter((item) => !item.ok);
fs.writeFileSync(path.join(evidence, "report.json"), `${JSON.stringify({
  schema: "lovelyhawk-host-key-probe/v1",
  status: failed.length === 0 ? "PASS" : "FAIL",
  generatedAt: new Date().toISOString(),
  checks,
}, null, 2)}\n`);
console.log(`${failed.length === 0 ? "PASS" : "FAIL"}: ${checks.length - failed.length}/${checks.length}; evidence in ${evidence}`);
process.exitCode = failed.length === 0 ? 0 : 1;
