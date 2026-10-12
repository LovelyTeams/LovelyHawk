// SFTP transfers in the Tauri terminal window against a real lab host, through
// the host commands the migration added: download through the save dialog
// (bytes compared with the host), upload through the open dialog with a plan,
// execution and host-side check, an editor save written back and checked on
// the host, and an editor save refused because the file changed on the host
// after it was opened, and the undo offered on a verified delete, permission
// change, rename (refused once the old name is taken) and new folder, and a
// download and an upload each stopped half-way with nothing half-written left.
// Everything happens in a fresh directory under /tmp on
// the lab host, removed at the end; native dialogs are answered by the
// debug-only scripted answers file.
//
//   LAB=ubuntu node ui/scripts/probe-sftp-transfers.mjs

import { execFileSync } from "node:child_process";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { labTarget } from "../../tools/lab/lab-target.mjs";
import { Sidecar, backendBinary, connect } from "../../tools/lab/rpc-harness.mjs";
import { attach, delay, launchDesktop, listTargets, waitFor } from "./cdp.mjs";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const executable = path.join(repositoryRoot, "target", "debug", process.platform === "win32" ? "lovelyhawk.exe" : "lovelyhawk");
const lab = process.env.LAB ?? "ubuntu";
const container = `lab-${lab}`;
const id = randomUUID().slice(0, 8);
const remoteDirectory = `/tmp/lh-sftp-${id}`;
const runRoot = path.join(repositoryRoot, "target", "desktop-debug", `sftp-${randomUUID()}`);
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
answer();
const sha256 = (data) => createHash("sha256").update(data).digest("hex");
function docker(...args) {
  // -e runs docker directly; "--" would hand the line to a shell first.
  return execFileSync("wsl.exe", ["-d", "Ubuntu", "-u", "root", "-e", "docker", ...args], { encoding: "utf8" });
}
const onHost = (script) => docker("exec", container, "sh", "-c", script);

const remoteText = `remote ${id}\nsecond line\n`;
docker("exec", "-e", `LH_TEXT=${Buffer.from(remoteText).toString("base64")}`, container, "sh", "-c",
  `mkdir -p ${remoteDirectory} && printf %s "$LH_TEXT" | base64 -d > ${remoteDirectory}/remote.txt` +
    ` && printf 'victim %s\\n' "${id}" > ${remoteDirectory}/victim.txt && chmod 640 ${remoteDirectory}/victim.txt`);
const uploadSource = path.join(files, `upload-${id}.txt`);
fs.writeFileSync(uploadSource, `uploaded ${id}\n${"x".repeat(2048)}\n`);

const sidecar = new Sidecar(backendBinary(), runRoot);
try {
  const status = await connect(sidecar, { ...labTarget(lab), name: `实验室 ${lab}` });
  if (status?.stage !== "connected") throw new Error(`lab connect failed: ${JSON.stringify(status)}`);
  await sidecar.call("ssh.binding.disconnect", { bindingHandle: status.bindingHandle });
} finally {
  sidecar.close();
}
await delay(500);

const port = 11_500 + Math.floor(Math.random() * 80);
const { child, output } = launchDesktop({ executable, archiveRoot: runRoot, port, extraEnv: { LOVELYHAWK_TEST_DIALOG_ANSWERS: answersFile } });
let exitCode = null;
child.once("exit", (code) => { exitCode = code; });
const errors = [];
const row = (name) => `[...document.querySelectorAll('section[aria-label="远程文件"] .sftp-browser-row')].find((candidate) => candidate.querySelector('.sftp-browser-row-label')?.textContent === ${JSON.stringify(name)})`;
const clickText = (selector, text) => `(() => { const element = [...document.querySelectorAll(${JSON.stringify(selector)})].find((candidate) => candidate.textContent.trim() === ${JSON.stringify(text)}); if (!element || element.disabled) return false; element.click(); return true; })()`;
try {
  const { session: main } = await attach(port, (url) => /^https?:\/\/tauri\.localhost\/(index\.html)?$/u.test(url));
  main.onEvent((method, params) => {
    if (method === "Runtime.exceptionThrown" || (method === "Runtime.consoleAPICalled" && params?.type === "error")) errors.push(JSON.stringify(params).slice(0, 1_500));
  });
  await main.send("Runtime.enable");
  await waitFor(() => main.evaluate("document.querySelector('[data-testid=\"sidebar-connect-target\"]') !== null"), { label: "the sidebar" });
  await main.evaluate("document.querySelector('[data-testid=\"sidebar-connect-target\"]').click(), true");
  await waitFor(() => main.evaluate(`(() => { const candidate = document.querySelector('.connection-list-row'); if (!candidate || candidate.disabled) return false; candidate.click(); return true; })()`), { timeoutMs: 15_000, label: "the saved connection" });
  await waitFor(() => main.evaluate(`(() => { const button = [...document.querySelectorAll('.connection-detail button')].find((candidate) => candidate.textContent.trim() === '连接目标' && !candidate.disabled); if (!button) return false; button.click(); return true; })()`), { timeoutMs: 15_000, label: "连接目标" });
  await waitFor(() => main.evaluate("document.querySelector('[data-testid=\"sidebar-open-terminal\"]') !== null && document.querySelector('.connection-manager-backdrop') === null"), { timeoutMs: 90_000, label: "the connection" });
  await main.evaluate("document.querySelector('[data-testid=\"sidebar-open-terminal\"]').click(), true");
  const { session: terminal } = await attach(port, (url) => url.includes("/terminal.html?window=terminal"), 30_000);
  await terminal.send("Runtime.enable");
  // The file panel opens with the window.
  await waitFor(() => terminal.evaluate("document.querySelector('[data-testid=\"toggle-remote-files\"]')?.getAttribute('aria-expanded') === 'true'"), { timeoutMs: 30_000, label: "the file panel" });
  for (const name of ["tmp", `lh-sftp-${id}`]) {
    await waitFor(() => terminal.evaluate(`(() => { const candidate = ${row(name)}; if (!candidate || candidate.disabled) return false; candidate.dispatchEvent(new MouseEvent('dblclick', { bubbles: true })); return true; })()`), { timeoutMs: 30_000, label: `the ${name} directory` });
    await delay(800);
  }
  await waitFor(() => terminal.evaluate(`${row("remote.txt")} !== undefined`), { timeoutMs: 30_000, label: "remote.txt" });

  // Download.
  const downloaded = path.join(files, "downloaded.txt");
  answer(downloaded);
  await terminal.evaluate(`${row("remote.txt")}.click(), true`);
  await waitFor(() => terminal.evaluate("document.querySelector('.sftp-browser-action.is-download')?.disabled === false"), { timeoutMs: 10_000, label: "下载 enabled" });
  await terminal.evaluate("document.querySelector('.sftp-browser-action.is-download').click(), true");
  const savedNotice = await waitFor(() => terminal.evaluate("[...document.querySelectorAll('.sftp-browser-page [role=\"status\"], .sftp-browser-notice, .sftp-browser-transfer')].map((node) => node.textContent).find((text) => /已保存为|下载失败/u.test(text)) ?? null"), { timeoutMs: 20_000, label: "the download notice" }).catch(() => null);
  const downloadedOk = fs.existsSync(downloaded) && fs.readFileSync(downloaded, "utf8") === remoteText;
  check("download saves the exact bytes where the save dialog pointed", downloadedOk && /已保存为 downloaded\.txt/u.test(savedNotice ?? ""), { notice: savedNotice, ok: downloadedOk });

  // Upload.
  answer(uploadSource);
  await terminal.evaluate("document.querySelector('.sftp-browser-action.is-upload').click(), true");
  await waitFor(() => terminal.evaluate(clickText(".sftp-operation-dialog button, [role=\"dialog\"] button", "生成计划")), { timeoutMs: 20_000, label: "生成计划" });
  const plan = await waitFor(() => terminal.evaluate("document.querySelector('[data-testid=\"sftp-operation-execute\"]') ? document.querySelector('[role=\"dialog\"]').textContent.slice(0, 300) : null"), { timeoutMs: 30_000, label: "the upload plan" }).catch(() => null);
  check("upload shows its plan before anything is written", plan !== null && plan.includes(path.basename(uploadSource)) && onHost(`ls ${remoteDirectory}`).indexOf(path.basename(uploadSource)) < 0, plan?.slice(0, 160));
  await terminal.evaluate("document.querySelector('[data-testid=\"sftp-operation-execute\"]').click(), true");
  const receipt = await waitFor(() => terminal.evaluate("document.querySelector('.sftp-operation-receipt')?.textContent ?? null"), { timeoutMs: 60_000, label: "the upload receipt" }).catch(() => null);
  const remoteHash = onHost(`sha256sum ${remoteDirectory}/${path.basename(uploadSource)} 2>/dev/null | cut -d' ' -f1`).trim();
  check("upload completes, passes its check, and the host holds the same bytes", receipt?.startsWith("已完成并通过校验") === true && remoteHash === sha256(fs.readFileSync(uploadSource)), { receipt: receipt?.slice(0, 120), remoteHash });
  check("the upload receipt reads in Chinese", receipt !== null && !/[A-Za-z]{4,}/u.test(receipt), receipt?.slice(0, 120));
  // A new file is checked by size alone, so taking it away again could take a
  // later edit with it: no undo is offered.
  check("an upload is not offered an undo", await terminal.evaluate("document.querySelector('[data-testid=\"sftp-operation-undo\"]') === null"));
  await terminal.evaluate(clickText(".sftp-operation-receipt ~ footer button, [role=\"dialog\"] footer button", "关闭"));
  await delay(500);

  // Undo, from the receipt of each operation that offers one.
  const setField = (value) => `(() => { const input = document.querySelector('[data-testid="sftp-operation-dialog"] input'); Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(input, ${JSON.stringify(value)}); input.dispatchEvent(new Event('input', { bubbles: true })); return true; })()`;
  async function runFromMenu(name, label, field = null) {
    await waitFor(() => terminal.evaluate(`(() => {
      const candidate = ${row(name)};
      if (!candidate) return false;
      const box = candidate.getBoundingClientRect();
      candidate.dispatchEvent(new MouseEvent('contextmenu', { bubbles: true, cancelable: true, clientX: box.left + 20, clientY: box.top + 5 }));
      const item = [...document.querySelectorAll('[role="menuitem"]')].find((entry) => entry.textContent.trim() === ${JSON.stringify(label)});
      if (!item || item.disabled) return false;
      item.click();
      return true;
    })()`), { timeoutMs: 20_000, label: `${label} on ${name}` });
    if (field !== null) await terminal.evaluate(setField(field));
    await waitFor(() => terminal.evaluate(clickText("[role=\"dialog\"] button", "生成计划")), { timeoutMs: 20_000, label: `${label}: 生成计划` });
    await waitFor(() => terminal.evaluate("document.querySelector('[data-testid=\"sftp-operation-execute\"]:not([disabled])') !== null"), { timeoutMs: 30_000, label: `${label}: the plan` });
    await terminal.evaluate("document.querySelector('[data-testid=\"sftp-operation-execute\"]').click(), true");
    return waitFor(() => terminal.evaluate("document.querySelector('.sftp-operation-receipt')?.textContent ?? null"), { timeoutMs: 60_000, label: `${label}: the receipt` }).catch(() => null);
  }
  async function undoFromReceipt(shot = null) {
    if (!(await terminal.evaluate("document.querySelector('[data-testid=\"sftp-operation-undo\"]:not([disabled])') !== null"))) return { offered: false };
    await terminal.evaluate("document.querySelector('[data-testid=\"sftp-operation-undo\"]').click(), true");
    await waitFor(() => terminal.evaluate("document.querySelector('[data-testid=\"sftp-operation-undo-ask\"]') !== null"), { timeoutMs: 10_000, label: "the undo question" });
    const question = await terminal.evaluate("document.querySelector('[data-testid=\"sftp-operation-undo-ask\"]').textContent");
    const focused = await terminal.evaluate("document.activeElement?.textContent?.trim() ?? null");
    if (shot !== null) await terminal.screenshot(path.join(evidence, `${shot}-question.png`));
    await terminal.evaluate("document.querySelector('[data-testid=\"sftp-operation-undo-confirm\"]').click(), true");
    const result = await waitFor(() => terminal.evaluate("document.querySelector('[data-testid=\"sftp-operation-undo-result\"]')?.textContent ?? null"), { timeoutMs: 60_000, label: "the undo result" }).catch(() => null);
    if (shot !== null) await terminal.screenshot(path.join(evidence, `${shot}-result.png`));
    const again = await terminal.evaluate("document.querySelector('[data-testid=\"sftp-operation-undo\"]') !== null");
    const focusAfter = await terminal.evaluate("document.activeElement?.textContent?.trim() ?? null");
    await terminal.evaluate(clickText("[role=\"dialog\"] footer button", "关闭"));
    await delay(500);
    return { offered: true, question, focused, result, again, focusAfter };
  }
  const victim = `${remoteDirectory}/victim.txt`;
  const victimHash = onHost(`sha256sum ${victim} | cut -d' ' -f1`).trim();
  const modeOf = (file) => onHost(`stat -c %a ${file} 2>/dev/null || echo gone`).trim();

  const removed = await runFromMenu("victim.txt", "删除");
  const goneAfterRemove = modeOf(victim) === "gone";
  const removeUndo = await undoFromReceipt("undo-remove");
  check("a verified delete offers an undo, asks first with focus on 不撤销, and names what comes back",
    removed?.startsWith("已完成并通过校验") === true && goneAfterRemove && removeUndo.offered &&
      removeUndo.focused === "不撤销" && removeUndo.question?.includes("移回原来的位置") === true,
    { removed: removed?.slice(0, 80), goneAfterRemove, focused: removeUndo.focused });
  check("the undone delete is back with the same bytes and permissions, verified on the host",
    removeUndo.result?.startsWith("已撤销") === true && onHost(`sha256sum ${victim} | cut -d' ' -f1`).trim() === victimHash && modeOf(victim) === "640",
    { result: removeUndo.result?.slice(0, 120), mode: modeOf(victim) });
  check("the undo is not offered twice and focus returns to 关闭", removeUndo.again === false && removeUndo.focusAfter === "关闭",
    { again: removeUndo.again, focusAfter: removeUndo.focusAfter });
  check("no copy of the deleted file is left behind after the undo",
    onHost(`find ${remoteDirectory} -name '*victim*' -path '*lovelyres-backups*' | wc -l`).trim() === "0");

  await waitFor(() => terminal.evaluate(`${row("victim.txt")} !== undefined`), { timeoutMs: 30_000, label: "victim.txt back in the list" });
  const chmodded = await runFromMenu("victim.txt", "设置权限", "600");
  const modeAfterChmod = modeOf(victim);
  const chmodUndo = await undoFromReceipt();
  check("a permission change is undone back to 640",
    chmodded?.startsWith("已完成并通过校验") === true && modeAfterChmod === "600" && chmodUndo.result?.startsWith("已撤销") === true && modeOf(victim) === "640",
    { modeAfterChmod, result: chmodUndo.result?.slice(0, 80), mode: modeOf(victim) });

  await waitFor(() => terminal.evaluate(`${row("victim.txt")} !== undefined`), { timeoutMs: 30_000, label: "victim.txt for the rename" });
  const renamed = await runFromMenu("victim.txt", "重命名", "moved.txt");
  // Something else takes the old name before the undo: putting the file back
  // there would overwrite it.
  onHost(`printf 'later business file\\n' > ${victim}`);
  const renameUndo = await undoFromReceipt("undo-refused");
  check("an undo is refused when the old name was taken after the rename, and both files stay as they are",
    renamed?.startsWith("已完成并通过校验") === true && renameUndo.result?.startsWith("没有撤销") === true &&
      renameUndo.result.includes("又有了变化") && onHost(`cat ${victim}`) === "later business file\n" &&
      onHost(`sha256sum ${remoteDirectory}/moved.txt | cut -d' ' -f1`).trim() === victimHash,
    { renamed: renamed?.slice(0, 60), result: renameUndo.result?.slice(0, 120) });

  const made = await runFromMenu("victim.txt", "新建文件夹", `made-${id}`);
  const madeBefore = onHost(`test -d ${remoteDirectory}/made-${id} && echo dir || echo none`).trim();
  const mkdirUndo = await undoFromReceipt();
  check("a new, still-empty folder is removed again by its undo",
    made?.startsWith("已完成并通过校验") === true && madeBefore === "dir" && mkdirUndo.result?.startsWith("已撤销") === true &&
      onHost(`test -e ${remoteDirectory}/made-${id} && echo present || echo gone`).trim() === "gone",
    { madeBefore, result: mkdirUndo.result?.slice(0, 80) });
  check("undo results read in Chinese", [removeUndo, chmodUndo, renameUndo, mkdirUndo].every((entry) => entry.result && !/[A-Za-z]{4,}/u.test(entry.result)));

  // Stop a download half-way: the local file it was writing must be gone.
  onHost(`truncate -s 6G ${remoteDirectory}/big.bin`);
  await terminal.evaluate("document.querySelector('.sftp-browser-action')?.click(), true");
  await waitFor(() => terminal.evaluate(`${row("big.bin")} !== undefined`), { timeoutMs: 30_000, label: "big.bin in the list" });
  const bigTarget = path.join(files, "big.bin");
  answer(bigTarget);
  await terminal.evaluate(`${row("big.bin")}.click(), true`);
  await waitFor(() => terminal.evaluate("document.querySelector('.sftp-browser-action.is-download')?.disabled === false"), { timeoutMs: 10_000, label: "下载 enabled for big.bin" });
  await terminal.evaluate("document.querySelector('.sftp-browser-action.is-download').click(), true");
  const running = await waitFor(async () => {
    const status = await terminal.evaluate("document.querySelector('.sftp-browser-transfer.is-running')?.textContent ?? null");
    return status !== null && fs.existsSync(bigTarget) && fs.statSync(bigTarget).size > 0 ? status : null;
  }, { timeoutMs: 30_000, label: "the download to start copying" }).catch(() => null);
  const copiedBeforeCancel = fs.existsSync(bigTarget) ? fs.statSync(bigTarget).size : 0;
  await terminal.screenshot(path.join(evidence, "download-running.png"));
  await terminal.evaluate("document.querySelector('[data-testid=\"sftp-cancel-download\"]')?.click(), true");
  const stoppedNotice = await waitFor(() => terminal.evaluate("[...document.querySelectorAll('.sftp-browser-transfer')].map((node) => node.textContent).find((text) => /已取消下载|已保存为|下载失败/u.test(text)) ?? null"), { timeoutMs: 60_000, label: "the download to stop" }).catch(() => null);
  check("a running download shows what it is copying and can be stopped",
    running?.includes("正在下载 big.bin") === true && copiedBeforeCancel > 0 && copiedBeforeCancel < 6 * 1024 ** 3 && stoppedNotice === "已取消下载，写到一半的文件已经删除。",
    { running, copiedBeforeCancel, stoppedNotice });
  check("the half-written download file is gone", !fs.existsSync(bigTarget), fs.existsSync(bigTarget) ? fs.statSync(bigTarget).size : null);
  await terminal.screenshot(path.join(evidence, "download-cancelled.png"));

  // Stop an upload half-way: nothing half-written stays on the host.
  const bigUpload = path.join(files, `big-upload-${id}.bin`);
  fs.writeFileSync(bigUpload, randomBytes(60 * 1024 * 1024));
  answer(bigUpload);
  await terminal.evaluate("document.querySelector('.sftp-browser-action.is-upload').click(), true");
  await waitFor(() => terminal.evaluate(clickText(".sftp-operation-dialog button, [role=\"dialog\"] button", "生成计划")), { timeoutMs: 20_000, label: "生成计划 (big upload)" });
  await waitFor(() => terminal.evaluate("document.querySelector('[data-testid=\"sftp-operation-execute\"]:not([disabled])') !== null"), { timeoutMs: 60_000, label: "the big upload plan" });
  await terminal.evaluate("document.querySelector('[data-testid=\"sftp-operation-execute\"]').click(), true");
  // Keep asking until the copy has registered and the switch reached it.
  const uploadReceipt = await waitFor(async () => {
    const receiptText = await terminal.evaluate("document.querySelector('.sftp-operation-receipt')?.textContent ?? null");
    if (receiptText !== null) return receiptText;
    await terminal.evaluate("(() => { const button = document.querySelector('[data-testid=\"sftp-cancel-upload\"]'); if (button && !button.disabled) button.click(); return true; })()");
    return null;
  }, { timeoutMs: 120_000, intervalMs: 50, label: "the big upload to stop" }).catch(() => null);
  await terminal.screenshot(path.join(evidence, "upload-cancelled.png"));
  const leftOnHost = onHost(`ls ${remoteDirectory}`).split(/\s+/u).filter((name) => name.startsWith("big-upload-"));
  check("a running upload can be stopped, and says so instead of 未通过校验",
    uploadReceipt?.startsWith("已取消上传") === true && uploadReceipt.includes("没有留下不完整的文件"), uploadReceipt?.slice(0, 120));
  check("nothing half-uploaded is left on the host", leftOnHost.length === 0, leftOnHost);
  await terminal.evaluate(clickText("[role=\"dialog\"] footer button", "关闭"));
  await delay(300);

  // Editor save, then a save refused because the host changed the file.
  async function openEditor() {
    await waitFor(() => terminal.evaluate(`(() => {
      const candidate = ${row("remote.txt")};
      if (!candidate) return false;
      const box = candidate.getBoundingClientRect();
      candidate.dispatchEvent(new MouseEvent('contextmenu', { bubbles: true, cancelable: true, clientX: box.left + 20, clientY: box.top + 5 }));
      const item = [...document.querySelectorAll('[role="menuitem"]')].find((entry) => entry.textContent.includes('编辑文本'));
      if (!item) return false;
      item.click();
      return true;
    })()`), { timeoutMs: 20_000, label: "编辑文本" });
    const { session: editor } = await attach(port, (url) => url.includes("/terminal.html?window=file-editor"), 30_000);
    await waitFor(() => editor.evaluate("(document.querySelector('.file-editor-text')?.value ?? '').length > 0"), { timeoutMs: 20_000, label: "the file text" });
    return editor;
  }
  const setText = (value) => `(() => { const area = document.querySelector('.file-editor-text'); Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value').set.call(area, ${JSON.stringify(value)}); area.dispatchEvent(new Event('input', { bubbles: true })); return true; })()`;
  let editor = await openEditor();
  const editedText = `${remoteText}edited in LovelyHawk ${id}\n`;
  await editor.evaluate(setText(editedText));
  await editor.evaluate("document.querySelector('.file-editor-save').click(), true");
  await waitFor(() => editor.evaluate(clickText(".file-editor-dialog button", "确认写入")), { timeoutMs: 20_000, label: "确认写入" });
  const written = await waitFor(() => editor.evaluate("[...document.querySelectorAll('.file-editor-notice, .file-editor-error')].map((node) => node.textContent).join(' ') || null"), { timeoutMs: 60_000, label: "the save receipt" }).catch(() => null);
  const onDisk = onHost(`cat ${remoteDirectory}/remote.txt`);
  check("an editor save is written back and checked on the host", written?.includes("已写回服务器并复核通过。") === true && onDisk === editedText, { written: written?.slice(0, 120), onDiskMatches: onDisk === editedText });
  check("the save receipt reads in Chinese", written !== null && !/[A-Za-z]{4,}/u.test(written), written?.slice(0, 120));
  await editor.evaluate("document.querySelector('[data-testid=\"file-editor-close\"]').click(), true");
  await waitFor(async () => !(await listTargets(port)).some((entry) => entry.url.includes("window=file-editor")), { timeoutMs: 10_000, label: "the editor to close" });

  editor = await openEditor();
  onHost(`printf 'changed on the host\\n' >> ${remoteDirectory}/remote.txt`);
  const hostVersion = onHost(`cat ${remoteDirectory}/remote.txt`);
  await editor.evaluate(setText(`${editedText}operator edit that must not overwrite\n`));
  await editor.evaluate("document.querySelector('.file-editor-save').click(), true");
  const refusal = await waitFor(async () => {
    const dialogOpen = await editor.evaluate("document.querySelector('.file-editor-dialog') !== null");
    if (dialogOpen) await editor.evaluate(clickText(".file-editor-dialog button", "确认写入"));
    return editor.evaluate("document.querySelector('.file-editor-error')?.textContent ?? null");
  }, { timeoutMs: 60_000, label: "the refusal" }).catch(() => null);
  const afterRace = onHost(`cat ${remoteDirectory}/remote.txt`);
  check("a save is refused when the file changed on the host after it was opened", refusal !== null && afterRace === hostVersion, { refusal, untouched: afterRace === hostVersion });
  await editor.screenshot(path.join(evidence, "editor-refusal.png"));
  await editor.evaluate("document.querySelector('[data-testid=\"file-editor-close\"]').click(), true");
  await delay(500);
  await editor.evaluate(clickText(".dialog-host button", "放弃修改并关闭")).catch(() => false);

  check("no console errors in the main window", errors.length === 0, errors.slice(0, 3));
  await main.evaluate("document.querySelector('[data-testid=\"sidebar-disconnect-target\"]').click(), true");
  await delay(1_000);
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
  schema: "lovelyhawk-sftp-transfers-probe/v1",
  status: failed.length === 0 ? "PASS" : "FAIL",
  lab,
  generatedAt: new Date().toISOString(),
  checks,
}, null, 2)}\n`);
console.log(`${failed.length === 0 ? "PASS" : "FAIL"}: ${checks.length - failed.length}/${checks.length}; evidence in ${evidence}`);
process.exitCode = failed.length === 0 ? 0 : 1;
