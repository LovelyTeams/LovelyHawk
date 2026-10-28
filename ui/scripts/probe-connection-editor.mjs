// The connection editor end to end, including a real key-based login.
//
// A throwaway ed25519 key is made on lab-ubuntu; its public half is added to
// root's authorized_keys with a marker comment and removed by that marker at
// the end. In the window the key file is picked through the system open
// dialog (answered by the debug dialog hook): picking the .pub half is
// refused with the reason, cancelling changes nothing, picking the key fills
// the path. The connection is saved with its classification and a note,
// reopened unchanged, and then really connects with that key after the first
// host-key confirmation. A second connection with a jump host using a
// certificate is saved and reopened with every jump field intact; its
// password is replaced and then removed without ever reaching the page; an
// out-of-range port is refused; an unsaved edit asks before it is dropped.
//
//   node ui/scripts/probe-connection-editor.mjs

import { execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { labTarget } from "../../tools/lab/lab-target.mjs";
import { attach, delay, launchDesktop, waitFor } from "./cdp.mjs";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const executable = path.join(repositoryRoot, "target", "debug", process.platform === "win32" ? "lovelyhawk.exe" : "lovelyhawk");
const id = randomUUID().slice(0, 8);
const marker = `lovelyhawk-probe-${id}`;
const runRoot = path.join(repositoryRoot, "target", "desktop-debug", `connection-editor-${randomUUID()}`);
const evidence = path.join(runRoot, "evidence");
const files = path.join(runRoot, "files");
const answersFile = path.join(runRoot, "dialog-answers.json");
const checks = [];
function check(name, ok, detail = null) {
  checks.push({ name, ok: Boolean(ok), detail });
  console.log(`${ok ? "PASS" : "FAIL"} ${name}${detail === null ? "" : ` — ${JSON.stringify(detail).slice(0, 400)}`}`);
}
fs.mkdirSync(evidence, { recursive: true });
fs.mkdirSync(files, { recursive: true });
const answer = (...answers) => fs.writeFileSync(answersFile, JSON.stringify(answers));
answer(null);
const onHost = (script) => execFileSync("wsl.exe", ["-d", "Ubuntu", "-u", "root", "-e", "docker", "exec", "lab-ubuntu", "sh", "-c", script], { encoding: "utf8" });

// The key pair, made on the lab host and copied out byte for byte.
onHost(`ssh-keygen -q -t ed25519 -N '' -C ${marker} -f /tmp/${marker}`);
const keyPath = path.join(files, `id_ed25519_${id}`);
const publicPath = `${keyPath}.pub`;
const certificatePath = path.join(files, `id_ed25519_${id}-cert.pub`);
fs.writeFileSync(keyPath, onHost(`cat /tmp/${marker}`));
fs.writeFileSync(publicPath, onHost(`cat /tmp/${marker}.pub`));
fs.writeFileSync(certificatePath, "not used for a login in this probe\n");
const hadAuthorizedKeys = onHost("test -f /root/.ssh/authorized_keys && echo yes || echo no").trim() === "yes";
onHost(`mkdir -p /root/.ssh && chmod 700 /root/.ssh && cat /tmp/${marker}.pub >> /root/.ssh/authorized_keys && chmod 600 /root/.ssh/authorized_keys && rm -f /tmp/${marker} /tmp/${marker}.pub`);
const lab = labTarget("ubuntu");
const password = `probe-${randomUUID()}`;
const replacement = `probe-${randomUUID()}`;

const port = 11_800 + Math.floor(Math.random() * 80);
const { child, output } = launchDesktop({ executable, archiveRoot: runRoot, port, extraEnv: { LOVELYHAWK_TEST_DIALOG_ANSWERS: answersFile } });
let exitCode = null;
child.once("exit", (code) => { exitCode = code; });
const errors = [];
const clickText = (selector, text) => `(() => { const element = [...document.querySelectorAll(${JSON.stringify(selector)})].find((candidate) => candidate.textContent.trim() === ${JSON.stringify(text)}); if (!element || element.disabled) return false; element.click(); return true; })()`;
const field = (label) => `[...document.querySelectorAll('.connection-editor .connection-field')].find((candidate) => candidate.querySelector('span')?.textContent.startsWith(${JSON.stringify(label)}))`;
const setField = (label, value) => `(() => {
  const input = ${field(label)}?.querySelector('input, textarea');
  if (!input) return false;
  const prototype = input instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
  Object.getOwnPropertyDescriptor(prototype, 'value').set.call(input, ${JSON.stringify(value)});
  input.dispatchEvent(new Event('input', { bubbles: true }));
  return true;
})()`;
const readField = (label) => `(${field(label)}?.querySelector('input, textarea')?.value ?? null)`;
const fieldLabel = (label) => `(${field(label)}?.querySelector('span')?.textContent ?? null)`;
const state = `({
  notice: document.querySelector('.connection-notice:not(.error)')?.textContent ?? null,
  error: document.querySelector('.connection-notice.error')?.textContent ?? null,
  editor: document.querySelector('.connection-editor') !== null,
  detail: document.querySelector('.connection-details-view h2')?.textContent ?? null,
  facts: Object.fromEntries([...document.querySelectorAll('.connection-fact-grid > div')].map((fact) => [fact.querySelector('span')?.textContent ?? '', fact.querySelector('strong')?.textContent ?? ''])),
  sections: [...document.querySelectorAll('.connection-detail-section')].map((section) => section.textContent),
})`;
try {
  const { session: main } = await attach(port, (url) => /^https?:\/\/tauri\.localhost\/(index\.html)?$/u.test(url));
  main.onEvent((method, params) => {
    if (method === "Runtime.exceptionThrown" || (method === "Runtime.consoleAPICalled" && params?.type === "error")) errors.push(JSON.stringify(params).slice(0, 1_500));
  });
  await main.send("Runtime.enable");
  const until = (predicate, label, timeoutMs = 15_000) => waitFor(async () => {
    const value = await main.evaluate(state);
    return predicate(value) ? value : null;
  }, { timeoutMs, label });
  async function startCreating() {
    await waitFor(() => main.evaluate(clickText(".connection-manager-header button", "新建连接")), { label: "新建连接" });
    await waitFor(() => main.evaluate("document.querySelector('.connection-editor') !== null"), { label: "the editor" });
  }
  async function save(name) {
    await main.evaluate("document.querySelector('.connection-editor button[type=\"submit\"]').click(), true");
    return until((value) => !value.editor && value.detail === name, `saving ${name}`).catch(async (error) => {
      console.error(JSON.stringify(await main.evaluate(state)).slice(0, 800));
      throw error;
    });
  }
  async function edit(name) {
    await waitFor(() => main.evaluate(`(() => { const row = [...document.querySelectorAll('.connection-list .connection-list-row')].find((candidate) => candidate.querySelector('strong')?.textContent === ${JSON.stringify(name)}); if (!row || row.disabled) return false; row.click(); return true; })()`), { label: `the ${name} row` });
    await until((value) => value.detail === name, `${name} selected`);
    await waitFor(() => main.evaluate(clickText(".connection-details-view footer button", "编辑配置")), { label: "编辑配置" });
    await waitFor(() => main.evaluate("document.querySelector('.connection-editor') !== null"), { label: "the editor" });
  }
  const choose = (accessibleName) => main.evaluate(`(() => { const button = document.querySelector(${JSON.stringify(`.connection-editor button[aria-label="${accessibleName}"]`)}); if (!button || button.disabled) return false; button.click(); return true; })()`);

  await waitFor(() => main.evaluate("(() => { const button = document.querySelector('[data-testid=\"sidebar-connect-target\"]'); if (!button) return false; button.click(); return true; })()"), { label: "连接管理" });
  await waitFor(() => main.evaluate("document.querySelector('.connection-manager') !== null"), { label: "the connection manager" });

  // A key-based connection, with its key picked through the dialog.
  await startCreating();
  for (const [label, value] of [["连接名称", "实验 私钥"], ["主机名或 IP", lab.host], ["端口", String(lab.port)], ["Linux 用户名", lab.username]]) {
    await main.evaluate(setField(label, value));
  }
  await main.evaluate(clickText(".connection-editor .auth-picker button", "SSH 私钥"));
  await waitFor(() => main.evaluate(`${field("私钥文件")} !== undefined`), { label: "the key field" });
  answer(publicPath);
  await choose("选择文件：目标私钥");
  let now = await until((value) => value.error !== null, "the refused public key");
  check("picking the .pub half is refused with the reason, and the path stays empty", now.error.includes("这是公钥文件") && await main.evaluate(readField("私钥文件")) === "", now.error);
  answer(null);
  await choose("选择文件：目标私钥");
  await delay(500);
  check("cancelling the dialog changes nothing", await main.evaluate(readField("私钥文件")) === "");
  answer(keyPath);
  await choose("选择文件：目标私钥");
  await waitFor(async () => await main.evaluate(readField("私钥文件")) === keyPath, { label: "the chosen key path" }).catch(() => undefined);
  now = await main.evaluate(state);
  check("picking the key fills its path and clears the earlier error", await main.evaluate(readField("私钥文件")) === keyPath && now.error === null, { value: await main.evaluate(readField("私钥文件")), error: now.error });
  for (const [label, value] of [["环境", "ctf"], ["角色", "web"], ["分组", "实验室"], ["标签", "probe，key"], ["备注", "<b>先核对指纹</b>"]]) {
    await main.evaluate(setField(label, value));
  }
  now = await save("实验 私钥");
  check("the key connection is saved and shown with its key file and classification",
    now.facts["认证方式"] === "SSH 私钥" && now.facts["凭据状态"] === "私钥（无已保存口令）" && now.facts["环境"] === "ctf" && now.facts["分组"] === "实验室" &&
    now.sections.some((section) => section.includes("认证文件") && section.includes(keyPath)) && now.sections.some((section) => section.includes("#probe") && section.includes("#key") && section.includes("<b>先核对指纹</b>")),
    { facts: now.facts });
  await edit("实验 私钥");
  check("reopening shows every field as saved", await main.evaluate(readField("私钥文件")) === keyPath && await main.evaluate(readField("标签")) === "key, probe" && await main.evaluate(readField("备注")) === "<b>先核对指纹</b>", {
    key: await main.evaluate(readField("私钥文件")), tags: await main.evaluate(readField("标签")),
  });
  await main.evaluate(clickText(".connection-editor footer button", "取消"));
  await until((value) => !value.editor, "the editor to close");

  // The real login with that key.
  await waitFor(() => main.evaluate(clickText(".connection-details-view header button", "连接目标")), { label: "连接目标" });
  const hostKey = await waitFor(() => main.evaluate("document.querySelector('.ssh-host-key-panel') ? document.querySelector('.ssh-host-key-panel').textContent : null"), { timeoutMs: 60_000, label: "the host-key prompt" });
  check("the first connection asks to verify the host key and says it will be remembered", hostKey.includes("SHA256:") && hostKey.includes("记在该连接里"), hostKey.slice(0, 160));
  await main.screenshot(path.join(evidence, "host-key.png"));
  await main.evaluate(clickText(".ssh-host-key-panel button", "我已独立核验，信任此指纹"));
  const connected = await waitFor(() => main.evaluate("document.querySelector('[data-testid=\"sidebar-disconnect-target\"]') !== null && document.querySelector('.connection-manager-backdrop') === null"), { timeoutMs: 90_000, label: "the key login" }).catch(() => false);
  check("the saved key really logs in", connected === true);
  if (connected === true) {
    await main.evaluate("document.querySelector('[data-testid=\"sidebar-disconnect-target\"]').click(), true");
    await waitFor(() => main.evaluate("document.querySelector('[data-testid=\"sidebar-disconnect-target\"]') === null"), { timeoutMs: 20_000, label: "the disconnect" });
  }
  await waitFor(() => main.evaluate("(() => { const button = document.querySelector('[data-testid=\"sidebar-connect-target\"]'); if (!button) return false; button.click(); return true; })()"), { label: "连接管理 again" });
  await waitFor(() => main.evaluate("document.querySelector('.connection-manager') !== null"), { label: "the connection manager again" });
  await waitFor(() => main.evaluate(`(() => { const row = [...document.querySelectorAll('.connection-list .connection-list-row')].find((candidate) => candidate.querySelector('strong')?.textContent === '实验 私钥'); if (!row || row.disabled) return false; row.click(); return true; })()`), { label: "the key row" });
  now = await until((value) => value.detail === "实验 私钥" && value.sections.some((section) => section.includes("SHA256:")), "the pinned fingerprint");
  check("after the login the host key is pinned on the connection", now.sections[0]?.includes("SHA256:") === true && now.facts["最近连接"] !== "尚未连接", { section: now.sections[0], last: now.facts["最近连接"] });

  // The pinned fingerprint survives a rename, and is dropped, after a warning, when the host changes.
  await edit("实验 私钥");
  await main.evaluate(setField("连接名称", "实验 私钥 改名"));
  check("renaming says nothing about the host key", await main.evaluate("document.querySelector('[data-testid=\"connection-pin-note\"]') === null"));
  now = await save("实验 私钥 改名");
  check("a rename keeps the pinned fingerprint", now.sections[0]?.includes("SHA256:") === true, now.sections[0]);
  await edit("实验 私钥 改名");
  await main.evaluate(setField("主机名或 IP", "192.0.2.99"));
  const pinNote = await waitFor(() => main.evaluate("document.querySelector('[data-testid=\"connection-pin-note\"]')?.textContent ?? null"), { label: "the pin note" }).catch(() => null);
  check("changing the host warns that the fingerprint must be verified again", pinNote?.includes("需要重新核验") === true, pinNote);
  now = await save("实验 私钥 改名");
  check("after saving, the old fingerprint is no longer trusted", now.sections[0]?.includes("首次连接时需要独立核验指纹") === true && !now.sections[0].includes("SHA256:"), now.sections[0]);
  await edit("实验 私钥 改名");
  await main.evaluate(setField("连接名称", "实验 私钥"));
  await main.evaluate(setField("主机名或 IP", lab.host));
  await save("实验 私钥");

  // SSH Agent: a malformed identity fingerprint is refused in words, a proper one is kept.
  await startCreating();
  for (const [label, value] of [["连接名称", "实验 Agent"], ["主机名或 IP", "192.0.2.30"], ["Linux 用户名", "ops"]]) {
    await main.evaluate(setField(label, value));
  }
  await main.evaluate(clickText(".connection-editor .auth-picker button", "SSH Agent"));
  await main.evaluate(setField("Agent 身份指纹", "md5:00:11:22"));
  await main.evaluate("document.querySelector('.connection-editor button[type=\"submit\"]').click(), true");
  now = await until((value) => value.error !== null, "the refused fingerprint");
  check("a malformed agent fingerprint is refused in plain words", now.editor && now.error.includes("SHA256") && !/Invalid|request/u.test(now.error), now.error);
  await main.evaluate(setField("Agent 身份指纹", "SHA256:dQJNxkQY3ME991ayA929K9CovIsEWz6vL00hDnfVH/Y"));
  now = await save("实验 Agent");
  check("an agent connection is saved with its identity", now.facts["认证方式"] === "SSH Agent" && now.facts["凭据状态"] === "本机 SSH Agent", now.facts);

  // An optional key passphrase is saved, then removed.
  await edit("实验 私钥");
  await main.evaluate(setField("私钥口令", password));
  now = await save("实验 私钥");
  check("a key passphrase is saved and leaves the form", now.facts["凭据状态"] === "私钥口令已保存", now.facts);
  await edit("实验 私钥");
  await main.evaluate(`(() => { const button = [...document.querySelectorAll('.connection-editor .connection-secret-field button')].find((candidate) => candidate.closest('.connection-secret-field').textContent.includes('私钥口令')); button.click(); return true; })()`);
  check("removing the saved passphrase is shown before saving", await main.evaluate(fieldLabel("私钥口令")) === "私钥口令（可选） · 将移除");
  now = await save("实验 私钥");
  check("after saving, the passphrase is gone", now.facts["凭据状态"] === "私钥（无已保存口令）", now.facts);

  // A jump host with a certificate, and a password that is replaced and then dropped.
  await startCreating();
  for (const [label, value] of [["连接名称", "实验 堡垒机"], ["主机名或 IP", "192.0.2.20"], ["Linux 用户名", "ops"], ["SSH 密码", password]]) {
    await main.evaluate(setField(label, value));
  }
  await main.evaluate(clickText(".connection-editor .connection-editor-section header button", "未启用"));
  await waitFor(() => main.evaluate(`${field("堡垒机地址")} !== undefined`), { label: "the jump fields" });
  for (const [label, value] of [["堡垒机地址", "192.0.2.21"], ["堡垒机端口", "2200"], ["堡垒机用户名", "jump"]]) {
    await main.evaluate(setField(label, value));
  }
  await main.evaluate(`(() => { const pickers = document.querySelectorAll('.connection-editor .auth-picker'); const button = [...pickers[1].querySelectorAll('button')].find((candidate) => candidate.textContent.trim() === 'OpenSSH 证书'); button.click(); return true; })()`);
  await waitFor(() => main.evaluate("document.querySelector('.connection-editor button[aria-label=\"选择文件：堡垒机用户证书\"]') !== null"), { label: "the jump certificate field" });
  answer(keyPath);
  await choose("选择文件：堡垒机私钥");
  await delay(500);
  answer(certificatePath);
  await choose("选择文件：堡垒机用户证书");
  await delay(500);
  now = await save("实验 堡垒机");
  check("a jump host with a certificate is saved and summarised", now.sections.some((section) => section.includes("jump@192.0.2.21:2200") && section.includes("OpenSSH 证书")) && now.facts["凭据状态"] === "密码已保存", { sections: now.sections });
  await edit("实验 堡垒机");
  const jump = {
    host: await main.evaluate(readField("堡垒机地址")), port: await main.evaluate(readField("堡垒机端口")), user: await main.evaluate(readField("堡垒机用户名")),
    key: await main.evaluate(`[...document.querySelectorAll('.connection-editor .connection-path-field input')].map((input) => input.value)`),
    password: await main.evaluate(fieldLabel("SSH 密码")), passwordValue: await main.evaluate(readField("SSH 密码")),
  };
  check("reopening keeps every jump-host field and shows the password only as saved", jump.host === "192.0.2.21" && jump.port === "2200" && jump.user === "jump" &&
    JSON.stringify(jump.key) === JSON.stringify([keyPath, certificatePath]) && jump.password === "SSH 密码 · 已有保存值" && jump.passwordValue === "", jump);

  await main.evaluate(setField("SSH 密码", replacement));
  now = await save("实验 堡垒机");
  check("a replaced password is saved and leaves the form", now.facts["凭据状态"] === "密码已保存" && await main.evaluate("[...document.querySelectorAll('input[type=\"password\"]')].every((input) => input.value === '')"), now.facts);
  await edit("实验 堡垒机");
  check("a required password offers no remove button that could only fail", await main.evaluate("[...document.querySelectorAll('.connection-editor .connection-secret-field')].every((candidate) => !candidate.textContent.includes('SSH 密码'))"));
  await main.evaluate("document.querySelector('.connection-editor .auth-picker') && [...document.querySelector('.connection-editor .auth-picker').querySelectorAll('button')].find((candidate) => candidate.textContent.trim() === '交互认证 / MFA').click(), true");
  const note = await waitFor(() => main.evaluate("document.querySelector('.connection-editor [role=\"note\"]:not([data-testid])')?.textContent ?? null"), { label: "the deletion note" }).catch(() => null);
  check("switching away from password login says the saved password will be deleted", note === "保存后会删除已保存的 SSH 密码。", note);
  now = await save("实验 堡垒机");
  check("after saving, the connection logs in interactively", now.facts["凭据状态"] === "连接时交互输入", now.facts);
  await edit("实验 堡垒机");
  await main.evaluate("[...document.querySelector('.connection-editor .auth-picker').querySelectorAll('button')].find((candidate) => candidate.textContent.trim() === '密码').click(), true");
  await waitFor(() => main.evaluate(`${field("SSH 密码")} !== undefined`), { label: "the password field" });
  check("switching back shows the password was really deleted", await main.evaluate(fieldLabel("SSH 密码")) === "SSH 密码 · 尚未保存");

  // An out-of-range port is refused and nothing changes.
  await main.evaluate(setField("端口", "70000"));
  await main.evaluate("document.querySelector('.connection-editor button[type=\"submit\"]').click(), true");
  now = await until((value) => value.error !== null, "the refused port");
  check("an out-of-range port is refused in plain words and the editor stays open", now.editor && /端口/u.test(now.error) && !/[A-Za-z]{5,}/u.test(now.error), now.error);

  // Leaving an unsaved edit asks first.
  await main.evaluate(clickText(".connection-editor footer button", "取消"));
  const ask = await waitFor(() => main.evaluate("document.querySelector('.dialog-host')?.textContent ?? null"), { label: "the discard question" });
  check("cancelling an unsaved edit asks before dropping it", ask.includes("放弃未保存的更改"), ask);
  await main.evaluate(clickText(".dialog-host button", "取消"));
  await delay(300);
  check("keeping the edit leaves it in the editor", await main.evaluate(readField("端口")) === "70000");
  await main.evaluate(clickText(".connection-editor footer button", "取消"));
  await waitFor(() => main.evaluate(clickText(".dialog-host button", "放弃更改")), { label: "放弃更改" });
  now = await until((value) => !value.editor && value.detail === "实验 堡垒机", "the discarded edit");
  check("discarding closes the editor and the saved port is unchanged", now.sections.length > 0 && !(await main.evaluate("document.body.innerText")).includes("70000"));

  const html = await main.evaluate("document.documentElement.outerHTML");
  check("neither password ever reached the page", !html.includes(password) && !html.includes(replacement));
  // The running app holds its instance lock open; every other file is read.
  const readable = fs.readdirSync(path.join(runRoot, "data"), { recursive: true }).filter((name) => !String(name).startsWith("webview2"))
    .map((name) => path.join(runRoot, "data", String(name))).filter((file) => fs.statSync(file).isFile())
    .flatMap((file) => { try { return [fs.readFileSync(file, "latin1")]; } catch { return []; } });
  const stored = readable.some((text) => text.includes(password) || text.includes(replacement));
  check("no data file holds either password in plain text", readable.length > 0 && !stored, { filesRead: readable.length });
  await main.screenshot(path.join(evidence, "connection-editor.png"));
  check("no console errors in the main window", errors.length === 0, errors.slice(0, 3));
  await main.evaluate("document.querySelector('[aria-label=\"关闭连接管理\"]')?.click(), true");
  await delay(500);
  await main.evaluate("document.querySelector('[data-testid=\"window-close\"]').click(), true");
  await waitFor(() => exitCode !== null, { timeoutMs: 15_000, label: "exit" }).catch(() => undefined);
  check("the app exits cleanly", exitCode === 0, exitCode);
} catch (error) {
  check("probe completed", false, error instanceof Error ? error.message : String(error));
  console.error(output.join("").slice(-3_000));
} finally {
  if (exitCode === null) child.kill();
  onHost(`sed -i '/${marker}/d' /root/.ssh/authorized_keys${hadAuthorizedKeys ? "" : " && { [ -s /root/.ssh/authorized_keys ] || rm -f /root/.ssh/authorized_keys; }"}`);
  check("the probe key was removed from the lab host", !onHost("cat /root/.ssh/authorized_keys 2>/dev/null || true").includes(marker));
}

const failed = checks.filter((entry) => !entry.ok);
fs.writeFileSync(path.join(evidence, "report.json"), `${JSON.stringify({
  schema: "lovelyhawk-connection-editor-probe/v1",
  status: failed.length === 0 ? "PASS" : "FAIL",
  generatedAt: new Date().toISOString(),
  checks,
}, null, 2)}\n`);
console.log(`${failed.length === 0 ? "PASS" : "FAIL"}: ${checks.length - failed.length}/${checks.length}; evidence in ${evidence}`);
process.exitCode = failed.length === 0 ? 0 : 1;
