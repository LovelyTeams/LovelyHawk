// Keyboard-interactive (MFA) login in the Tauri window against a real server.
//
// No lab host offers keyboard-interactive as built, so this probe turns it on
// in lab-rocky for its own run only — one sshd drop-in, checked with `sshd -t`
// before the reload — and removes it again in `finally`, confirming the setting
// is back to what it was. PAM then asks for the password as a server prompt,
// which is exactly the conversation an MFA server holds.
//
// Checked: the prompt is shown as the server sent it, the answer field hides
// what is typed and has focus; a wrong answer is refused and says so; the right
// one connects; nothing typed into the prompt is written to the data root.
//
//   node ui/scripts/probe-mfa.mjs

import { execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { labTarget } from "../../tools/lab/lab-target.mjs";
import { attach, launchDesktop, waitFor } from "./cdp.mjs";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const executable = path.join(repositoryRoot, "target", "debug", process.platform === "win32" ? "lovelyhawk.exe" : "lovelyhawk");
const runRoot = path.join(repositoryRoot, "target", "desktop-debug", `mfa-${randomUUID()}`);
const evidence = path.join(runRoot, "evidence");
const answersFile = path.join(runRoot, "dialog-answers.json");
const exportFile = path.join(runRoot, "files", "connections.json");
const container = "lab-rocky";
const dropIn = "/etc/ssh/sshd_config.d/00-lovelyhawk-mfa-probe.conf";
const lab = labTarget("rocky");
const wrong = `wrong-${randomUUID().slice(0, 8)}`;
const checks = [];
function check(name, ok, detail = null) {
  checks.push({ name, ok: Boolean(ok), detail });
  console.log(`${ok ? "PASS" : "FAIL"} ${name}${detail === null ? "" : ` — ${JSON.stringify(detail).slice(0, 300)}`}`);
}
const onHost = (script) => execFileSync("wsl.exe", ["-d", "Ubuntu", "-u", "root", "-e", "docker", "exec", container, "sh", "-c", script], { encoding: "utf8" }).trim();
const kbdSetting = () => onHost("sshd -T 2>/dev/null | grep -i '^kbdinteractiveauthentication'");
const reloadSshd = () => onHost("kill -HUP $(pgrep -f 'sshd: /usr/sbin/sshd -D' | head -1)");

fs.mkdirSync(evidence, { recursive: true });
fs.mkdirSync(path.dirname(exportFile), { recursive: true });
fs.writeFileSync(answersFile, JSON.stringify([exportFile]));
fs.writeFileSync(exportFile, JSON.stringify({
  format: "lovelyres-connections",
  schema_version: 1,
  exported_at: new Date().toISOString(),
  connections: [{
    name: "交互认证 rocky", host: lab.host, port: lab.port, username: lab.username, auth_method: "keyboard-interactive",
    private_key_path: null, certificate_path: null, agent_identity_fingerprint: null, jump_host: null,
    tags: [], notes: null, environment: null, role: null, group: null, host_key_fingerprint: null,
  }],
}, null, 2));

const before = kbdSetting();
let enabled = false;
let child = null;
let exitCode = null;
let output = [];
try {
  check("lab-rocky does not offer keyboard-interactive before the run", before === "kbdinteractiveauthentication no", before);
  if (onHost(`test -e ${dropIn} && echo yes || echo no`) !== "no") throw new Error("a drop-in of this name already exists; refusing to touch it");
  onHost(`printf 'KbdInteractiveAuthentication yes\\n' > ${dropIn} && sshd -t`);
  enabled = true;
  reloadSshd();
  await waitFor(() => kbdSetting() === "kbdinteractiveauthentication yes", { timeoutMs: 10_000, label: "sshd to reload" });

  const port = 12_000 + Math.floor(Math.random() * 80);
  ({ child, output } = launchDesktop({ executable, archiveRoot: runRoot, port, extraEnv: { LOVELYHAWK_TEST_DIALOG_ANSWERS: answersFile } }));
  child.once("exit", (code) => { exitCode = code; });
  const errors = [];
  const { session: main } = await attach(port, (url) => /^https?:\/\/tauri\.localhost\/(index\.html)?$/u.test(url));
  main.onEvent((method, params) => {
    if (method === "Runtime.exceptionThrown" || (method === "Runtime.consoleAPICalled" && params?.type === "error")) errors.push(JSON.stringify(params).slice(0, 1_500));
  });
  await main.send("Runtime.enable");
  const clickText = (selector, text) => `(() => { const element = [...document.querySelectorAll(${JSON.stringify(selector)})].find((candidate) => candidate.textContent.trim() === ${JSON.stringify(text)}); if (!element || element.disabled) return false; element.click(); return true; })()`;
  await waitFor(() => main.evaluate("(() => { const button = document.querySelector('[data-testid=\"sidebar-connect-target\"]'); if (!button) return false; button.click(); return true; })()"), { label: "连接管理" });
  await waitFor(() => main.evaluate("document.querySelector('[data-testid=\"connection-import\"]') !== null"), { label: "导入" });
  await waitFor(() => main.evaluate("(() => { const button = document.querySelector('[data-testid=\"connection-import\"]'); if (!button || button.disabled) return false; button.click(); return true; })()"), { label: "导入 enabled" });
  await waitFor(() => main.evaluate("[...document.querySelectorAll('.connection-list .connection-list-row strong')].some((name) => name.textContent === '交互认证 rocky')"), { timeoutMs: 30_000, label: "the imported connection" });
  const selectRow = () => waitFor(() => main.evaluate(`(() => { const row = [...document.querySelectorAll('.connection-list .connection-list-row')].find((candidate) => candidate.querySelector('strong')?.textContent === '交互认证 rocky'); if (!row || row.disabled) return false; row.click(); return true; })()`), { label: "the row" });

  /** Starts a connection, trusts the first-contact key, and returns the MFA panel. */
  async function reachPrompt() {
    await selectRow();
    await waitFor(() => main.evaluate(clickText(".connection-details-view header button", "连接目标")), { label: "连接目标" });
    return waitFor(async () => {
      if (await main.evaluate("document.querySelector('[data-testid=\"ssh-host-key-trust\"]') !== null")) {
        await main.evaluate("document.querySelector('[data-testid=\"ssh-host-key-trust\"]').click(), true");
        return null;
      }
      return main.evaluate(`(() => {
        const panel = document.querySelector('.ssh-mfa-panel');
        if (panel === null) return null;
        const input = panel.querySelector('input');
        return { text: panel.textContent, type: input?.type ?? null, focused: document.activeElement === input };
      })()`);
    }, { timeoutMs: 90_000, label: "the server prompt" });
  }
  async function answer(text) {
    const sent = await main.evaluate(`(() => {
      const form = document.querySelector('form.ssh-mfa-panel');
      const input = form?.querySelector('input');
      if (!form || !input) return document.querySelector('.ssh-attempt-dialog')?.textContent?.slice(0, 200) ?? 'no dialog';
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(input, ${JSON.stringify(text)});
      input.dispatchEvent(new Event('input', { bubbles: true }));
      form.requestSubmit();
      return true;
    })()`);
    if (sent !== true) throw new Error(`no prompt to answer: ${sent}`);
  }

  const prompt = await reachPrompt();
  check("the server's prompt is shown as asked, in a hidden field that has focus",
    /password/iu.test(prompt.text) && prompt.type === "password" && prompt.focused, prompt);
  await main.screenshot(path.join(evidence, "mfa-prompt.png"));

  // A wrong answer: PAM may ask again or the server may give up; either way it must not connect.
  await answer(wrong);
  const afterWrong = await waitFor(() => main.evaluate(`(() => {
    const failure = document.querySelector('.ssh-failure-panel')?.textContent ?? null;
    const again = document.querySelector('.ssh-mfa-panel input')?.value === '' ? 'asked-again' : null;
    return failure ?? again;
  })()`), { timeoutMs: 60_000, label: "the wrong answer's outcome" }).catch(() => null);
  const connectedAfterWrong = await main.evaluate("document.querySelector('[data-testid=\"sidebar-disconnect-target\"]') !== null");
  if (afterWrong === null) {
    await main.screenshot(path.join(evidence, "after-wrong.png"));
    console.log("page errors:", JSON.stringify(errors.slice(0, 3)).slice(0, 3_000));
    console.log("location:", await main.evaluate("location.href"));
    console.log("after wrong:", await main.evaluate("document.querySelector('.ssh-attempt-dialog')?.textContent?.slice(0, 300) ?? 'no dialog'"),
      await main.evaluate("JSON.stringify({ value: document.querySelector('.ssh-mfa-panel input')?.value ?? null, error: document.querySelector('.ssh-attempt-error')?.textContent ?? null })"));
  }
  check("a wrong answer does not connect and either asks again or says authentication failed",
    !connectedAfterWrong && (afterWrong === "asked-again" || afterWrong?.includes("认证没有通过") === true), afterWrong?.slice(0, 120));
  if (afterWrong !== "asked-again") {
    await main.evaluate(clickText(".ssh-attempt-dialog footer button", "关闭"));
    await waitFor(() => main.evaluate("document.querySelector('.ssh-attempt-dialog') === null"), { label: "the attempt to close" });
    await reachPrompt();
  }
  await answer(lab.password);
  const connected = await waitFor(() => main.evaluate("document.querySelector('[data-testid=\"sidebar-disconnect-target\"]') !== null && document.querySelector('.connection-manager-backdrop') === null"), { timeoutMs: 90_000, label: "the login" }).catch(() => false);
  check("the right answer connects", connected === true);
  if (connected === true) {
    await main.evaluate("document.querySelector('[data-testid=\"sidebar-disconnect-target\"]').click(), true");
    await waitFor(() => main.evaluate("document.querySelector('[data-testid=\"sidebar-disconnect-target\"]') === null"), { timeoutMs: 20_000, label: "the disconnect" });
  }
  check("no console errors", errors.length === 0, errors.slice(0, 3));
  await main.evaluate("document.querySelector('[data-testid=\"window-close\"]').click(), true");
  await waitFor(() => exitCode !== null, { timeoutMs: 20_000, label: "exit" }).catch(() => undefined);
  check("the app exits cleanly", exitCode === 0, exitCode);

  // Nothing typed into the prompt is kept: search every file the run wrote.
  const leaked = [];
  const walk = (directory) => {
    for (const item of fs.readdirSync(directory, { withFileTypes: true })) {
      const full = path.join(directory, item.name);
      if (item.isDirectory()) walk(full);
      else if (item.isFile() && fs.statSync(full).size < 64 * 1024 * 1024) {
        const bytes = fs.readFileSync(full);
        if (bytes.includes(wrong) || bytes.includes(lab.password)) leaked.push(path.relative(runRoot, full));
      }
    }
  };
  walk(path.join(runRoot, "data"));
  check("neither answer is written anywhere in the data root", leaked.length === 0, leaked);
} catch (error) {
  check("probe completed", false, error instanceof Error ? error.message : String(error));
  console.error(output.join("").slice(-3_000));
} finally {
  if (child !== null && exitCode === null) child.kill();
  if (enabled) {
    onHost(`rm -f ${dropIn}`);
    reloadSshd();
    await waitFor(() => kbdSetting() === before, { timeoutMs: 10_000, label: "sshd to be restored" }).catch(() => undefined);
  }
  check("lab-rocky is back to its own setting", kbdSetting() === before && onHost(`test -e ${dropIn} && echo yes || echo no`) === "no", kbdSetting());
}

const failed = checks.filter((item) => !item.ok);
fs.writeFileSync(path.join(evidence, "report.json"), `${JSON.stringify({
  schema: "lovelyhawk-mfa-probe/v1",
  status: failed.length === 0 ? "PASS" : "FAIL",
  generatedAt: new Date().toISOString(),
  checks,
}, null, 2)}\n`);
console.log(`${failed.length === 0 ? "PASS" : "FAIL"}: ${checks.length - failed.length}/${checks.length}; evidence in ${evidence}`);
process.exitCode = failed.length === 0 ? 0 : 1;
