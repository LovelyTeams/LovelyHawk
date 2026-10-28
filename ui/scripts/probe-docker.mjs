// The Docker page against a real daemon: svc-docker from tools/lab/orchestration,
// which runs its own Docker with 17 planted containers.
//
// Checked in the window the operator uses: the container list, the security
// audit naming the planted risks, logs and inspect for a container, the
// image/network/volume tabs, a lifecycle action that reaches its state
// (stopped-worker started and stopped again, both verified on the host), one
// that cannot (stopped-batch exits at once: the check must fail and the start
// be rolled back), a container terminal that really runs inside app-shell, and
// the page emptying on disconnect. Containers are left as the lab planted them.
//
//   node ui/scripts/probe-docker.mjs

import { execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { labTarget } from "../../tools/lab/lab-target.mjs";
import { Sidecar, backendBinary, connect } from "../../tools/lab/rpc-harness.mjs";
import { CdpSession, attach, delay, launchDesktop, listTargets, waitFor } from "./cdp.mjs";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const executable = path.join(repositoryRoot, "target", "debug", process.platform === "win32" ? "lovelyhawk.exe" : "lovelyhawk");
const runRoot = path.join(repositoryRoot, "target", "desktop-debug", `docker-${randomUUID()}`);
// Unique per run, so a process some earlier run left behind is never counted.
const sleepSeconds = 40_000 + Math.floor(Math.random() * 9_000);
const evidence = path.join(runRoot, "evidence");
const checks = [];
function check(name, ok, detail = null) {
  checks.push({ name, ok: Boolean(ok), detail });
  console.log(`${ok ? "PASS" : "FAIL"} ${name}${detail === null ? "" : ` — ${JSON.stringify(detail).slice(0, 400)}`}`);
}
fs.mkdirSync(evidence, { recursive: true });
/** The daemon inside svc-docker, read directly so "verified" is not the tool grading itself. */
const inner = (format, name) => execFileSync("wsl.exe", ["-d", "Ubuntu", "-u", "root", "-e", "docker", "exec", "svc-docker", "docker", "inspect", "--format", format, name], { encoding: "utf8" }).trim();
const running = (name) => inner("{{.State.Running}}", name) === "true";
/** A shell inside app-shell, and one on svc-docker itself, for the file checks. */
const inApp = (script) => execFileSync("wsl.exe", ["-d", "Ubuntu", "-u", "root", "-e", "docker", "exec", "svc-docker", "docker", "exec", "app-shell", "sh", "-c", script], { encoding: "utf8" });
const onDockerHost = (script) => execFileSync("wsl.exe", ["-d", "Ubuntu", "-u", "root", "-e", "docker", "exec", "svc-docker", "sh", "-c", script], { encoding: "utf8" });
const fileId = randomUUID().slice(0, 8);
const scratchName = `lh-file-${fileId}.conf`;
const scratch = `/tmp/${scratchName}`;
const copied = `/tmp/lh-copy-${fileId}.conf`;
if (running("stopped-worker") || running("stopped-batch")) throw new Error("svc-docker is not in its planted state; restart it before running this probe.");

const sidecar = new Sidecar(backendBinary(), runRoot);
try {
  const status = await connect(sidecar, { ...labTarget("docker"), name: "实验 Docker" });
  if (status?.stage !== "connected") throw new Error(`lab connect failed: ${JSON.stringify(status)}`);
  await sidecar.call("ssh.binding.disconnect", { bindingHandle: status.bindingHandle });
} finally {
  sidecar.close();
}
await delay(500);

const port = 12_100 + Math.floor(Math.random() * 80);
const { child, output } = launchDesktop({ executable, archiveRoot: runRoot, port });
let exitCode = null;
let mainSession = null;
child.once("exit", (code) => { exitCode = code; });
const errors = [];
// Only what the operator could click: a button inside a hidden pane (the file
// browser while the editor is shown) has the same words but is not on screen.
const clickText = (selector, text) => `(() => { const element = [...document.querySelectorAll(${JSON.stringify(selector)})].find((candidate) => candidate.textContent.trim() === ${JSON.stringify(text)} && candidate.closest('[hidden]') === null); if (!element || element.disabled) return false; element.click(); return true; })()`;
const rowOf = (name) => `[...document.querySelectorAll('.docker-page tbody tr')].find((row) => row.querySelector('.docker-row-button')?.textContent.trim() === ${JSON.stringify(name)})`;
try {
  const { session: main } = await attach(port, (url) => /^https?:\/\/tauri\.localhost\/(index\.html)?$/u.test(url));
  mainSession = main;
  main.onEvent((method, params) => {
    if (method === "Runtime.exceptionThrown" || (method === "Runtime.consoleAPICalled" && params?.type === "error")) errors.push(JSON.stringify(params).slice(0, 1_500));
  });
  await main.send("Runtime.enable");
  await waitFor(() => main.evaluate("(() => { const button = document.querySelector('[data-testid=\"sidebar-connect-target\"]'); if (!button) return false; button.click(); return true; })()"), { label: "连接管理" });
  await waitFor(() => main.evaluate(`(() => { const row = document.querySelector('.connection-list .connection-list-row'); if (!row || row.disabled) return false; row.click(); return true; })()`), { timeoutMs: 15_000, label: "the saved connection" });
  await waitFor(() => main.evaluate(`(() => { const button = [...document.querySelectorAll('.connection-detail button')].find((candidate) => candidate.textContent.trim() === '连接目标' && !candidate.disabled); if (!button) return false; button.click(); return true; })()`), { timeoutMs: 15_000, label: "连接目标" });
  await waitFor(() => main.evaluate("document.querySelector('[data-testid=\"sidebar-disconnect-target\"]') !== null && document.querySelector('.connection-manager-backdrop') === null"), { timeoutMs: 90_000, label: "the connection" });
  await main.evaluate(`(() => { const button = [...document.querySelectorAll('.nav-item')].find((candidate) => candidate.querySelector('strong')?.textContent === 'Docker'); button?.click(); return true; })()`);

  // The container list: ten to a page, so each planted one is found through the page's own search.
  const daemonCount = Number(execFileSync("wsl.exe", ["-d", "Ubuntu", "-u", "root", "-e", "docker", "exec", "svc-docker", "sh", "-c", "docker ps -aq | wc -l"], { encoding: "utf8" }).trim());
  await waitFor(() => main.evaluate("document.querySelectorAll('.docker-page tbody .docker-row-button').length > 0"), { timeoutMs: 90_000, label: "the containers" });
  const filterTo = (value) => main.evaluate(`(() => { const input = document.querySelector('input[aria-label="搜索容器"]'); Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(input, ${JSON.stringify(value)}); input.dispatchEvent(new Event('input', { bubbles: true })); return true; })()`);
  const totals = await main.evaluate("({ tab: [...document.querySelectorAll('.docker-tabs .docker-tab')].find((tab) => tab.textContent.startsWith('容器'))?.textContent.trim() ?? null, footer: document.querySelector('.docker-table-footer .docker-muted')?.textContent ?? null })");
  check("the container count matches the daemon, on the tab and under the table", totals.tab === `容器${daemonCount}` && totals.footer === `共 ${daemonCount} 条`, { ...totals, daemonCount });
  const planted = ["legacy-agent", "ci-runner", "app-shell", "stopped-worker", "stopped-batch", "incident-collector"];
  const found = [];
  for (const name of planted) {
    await filterTo(name);
    if (await waitFor(() => main.evaluate(`${rowOf(name)} !== undefined`), { timeoutMs: 5_000, label: name }).catch(() => false)) found.push(name);
  }
  await filterTo("");
  check("every planted container, running or stopped, can be found by name", found.length === planted.length, { missing: planted.filter((name) => !found.includes(name)) });
  await main.screenshot(path.join(evidence, "docker-containers.png"));

  // The security audit names what was planted.
  await main.evaluate(clickText(".docker-tabs .docker-tab", "安全审计") + " || " + `(() => { const tab = [...document.querySelectorAll('.docker-tabs .docker-tab')].find((candidate) => candidate.textContent.includes('安全审计')); tab?.click(); return true; })()`);
  const audit = await waitFor(() => main.evaluate("(() => { const findings = [...document.querySelectorAll('.docker-finding')].map((finding) => finding.textContent); return findings.length > 0 ? findings : null; })()"), { timeoutMs: 90_000, label: "the audit" }).catch(() => null);
  const named = (container) => (audit ?? []).some((text) => text.includes(container));
  check("the audit finds the planted risks (privileged, socket mount, host network, host PID)", ["legacy-agent", "ci-runner", "edge-proxy", "monitor-sidecar"].every(named), { findings: audit?.length, missing: ["legacy-agent", "ci-runner", "edge-proxy", "monitor-sidecar"].filter((name) => !named(name)) });
  await main.screenshot(path.join(evidence, "docker-audit.png"));

  // Images, networks, volumes.
  for (const [tab, selector] of [["镜像", ".docker-page [role='listitem'], .docker-page .docker-image-card, .docker-page article"], ["网络", ".docker-page [role='listitem']"], ["存储卷", ".docker-page [role='listitem']"]]) {
    await main.evaluate(`(() => { const button = [...document.querySelectorAll('.docker-tabs .docker-tab')].find((candidate) => candidate.textContent.startsWith(${JSON.stringify(tab)})); button?.click(); return true; })()`);
    const items = await waitFor(() => main.evaluate(`document.querySelectorAll(${JSON.stringify(selector)}).length || null`), { timeoutMs: 60_000, label: tab }).catch(() => null);
    check(`the ${tab} tab lists what the daemon holds`, items !== null && items > 0, items);
  }

  // Logs and inspect for one container.
  await main.evaluate(`(() => { const button = [...document.querySelectorAll('.docker-tabs .docker-tab')].find((candidate) => candidate.textContent.startsWith('容器')); button?.click(); return true; })()`);
  await filterTo("incident-collector");
  await waitFor(() => main.evaluate(`${rowOf("incident-collector")} !== undefined`), { timeoutMs: 60_000, label: "incident-collector" });
  await main.evaluate(`${rowOf("incident-collector")}.querySelector('.docker-row-button').click(), true`);
  const inspected = await waitFor(() => main.evaluate("(() => { const dialog = document.querySelector('[data-testid=\"docker-detail-dialog\"]'); const text = dialog?.textContent ?? ''; return text.includes('容器信息') && !text.includes('正在读取') ? text : null; })()"), { timeoutMs: 60_000, label: "the inspection" }).catch(() => null);
  check("selecting a container shows its inspected details, mounts and networks", inspected !== null && inspected.includes("incident-collector") && inspected.includes("挂载卷") && inspected.includes("网络连接"), inspected?.slice(0, 200));
  await main.screenshot(path.join(evidence, "docker-inspect.png"));

  // 排查 in the same dialog: what changed since the image and what runs, both
  // read from the host. The process count is checked against the daemon's own.
  await main.evaluate("document.querySelector('[data-testid=\"docker-forensics-changes\"]')?.click(), true");
  await main.evaluate("document.querySelector('[data-testid=\"docker-forensics-processes\"]')?.click(), true");
  const forensics = await waitFor(() => main.evaluate("(() => { const panel = document.querySelector('[data-testid=\"docker-forensics\"]'); if (!panel || panel.querySelector('[role=\"alert\"]')) return panel?.querySelector('[role=\"alert\"]')?.textContent ?? null; const rows = panel.querySelectorAll('.docker-forensics-table tbody tr').length; const changes = panel.querySelectorAll('.docker-forensics-list li').length; const unchanged = panel.textContent.includes('和镜像相比没有任何改动'); return rows > 0 && (changes > 0 || unchanged) ? { rows, changes, unchanged } : null; })()"), { timeoutMs: 60_000, label: "the 排查 panel" }).catch(() => null);
  const daemonProcesses = Number(onDockerHost("docker top incident-collector 2>/dev/null | tail -n +2 | wc -l").trim());
  check("排查 reads the container's processes and filesystem changes from the host", typeof forensics === "object" && forensics !== null && forensics.rows === daemonProcesses, { forensics, daemonProcesses });
  await main.screenshot(path.join(evidence, "docker-forensics.png"));
  await waitFor(() => main.evaluate(clickText(".docker-page button", "读取日志") + " || " + `(() => { const header = [...document.querySelectorAll('.docker-page h3')].find((node) => node.textContent === '最近日志'); const button = header?.closest('div')?.parentElement?.querySelector('button'); if (!button || button.disabled) return false; button.click(); return true; })()`), { timeoutMs: 30_000, label: "the logs button" });
  const logs = await waitFor(() => main.evaluate("(() => { const pre = document.querySelector('.docker-page pre'); return pre && pre.textContent.trim().length > 0 ? pre.textContent : null; })()"), { timeoutMs: 60_000, label: "the logs" }).catch(() => null);
  check("the logs of a running container are read", logs !== null && logs.split("\n").length > 1, logs?.slice(0, 120));

  // A start that reaches its state, then the stop that puts it back.
  async function act(container, action) {
    await filterTo(container);
    await waitFor(() => main.evaluate(`(() => { const row = ${rowOf(container)}; const button = row?.querySelector('[data-testid="docker-action-${action}"]'); if (!button || button.disabled) return false; button.click(); return true; })()`), { timeoutMs: 60_000, label: `${action} ${container}` });
    await waitFor(() => main.evaluate("document.querySelector('[data-testid=\"docker-action-execute\"]')?.disabled === false"), { timeoutMs: 60_000, label: `the ${action} plan` });
    const plan = await main.evaluate("document.querySelector('[data-testid=\"docker-action-dialog\"]').textContent");
    await main.evaluate("document.querySelector('[data-testid=\"docker-action-execute\"]').click(), true");
    const receipt = await waitFor(() => main.evaluate("(() => { const summary = document.querySelector('.docker-action-summary'); return summary ? document.querySelector('[data-testid=\"docker-action-dialog\"]').textContent : null; })()"), { timeoutMs: 120_000, label: `the ${action} receipt` });
    await main.evaluate(clickText("[data-testid='docker-action-dialog'] footer button", "关闭"));
    await delay(1_500);
    return { plan, receipt };
  }
  let result = await act("stopped-worker", "start");
  check("starting a stopped container shows its plan, then reaches the state on the host", result.plan.includes("stopped-worker") && result.receipt.includes("已完成，并在目标机上核对过。") && running("stopped-worker"), { receipt: result.receipt.slice(0, 160), running: running("stopped-worker") });
  await waitFor(() => main.evaluate(`(${rowOf("stopped-worker")})?.querySelector('[data-testid="docker-action-stop"]') != null`), { timeoutMs: 60_000, label: "the refreshed row" }).catch(() => undefined);
  result = await act("stopped-worker", "stop");
  check("stopping it again is verified too, leaving it as planted", result.receipt.includes("已完成，并在目标机上核对过。") && !running("stopped-worker"), { receipt: result.receipt.slice(0, 160), running: running("stopped-worker") });

  // A start whose container exits at once: the command succeeds, the state is never reached.
  result = await act("stopped-batch", "start");
  check("a start that never reaches the running state fails its check and is rolled back", result.receipt.includes("没有达到预期状态。") && result.receipt.includes("已还原到操作前的状态") && !running("stopped-batch"), { receipt: result.receipt.slice(0, 200), running: running("stopped-batch") });
  await main.screenshot(path.join(evidence, "docker-action-failed.png"));

  // A file inside app-shell: open, edit, save with a plan, read back on the container.
  inApp(`printf 'listen=80\\nname=${fileId}\\n' > ${scratch}`);
  const original = inApp(`cat ${scratch}`);
  await filterTo("app-shell");
  await waitFor(() => main.evaluate(`(() => { const button = (${rowOf("app-shell")})?.querySelector('[data-testid="docker-open-files"]'); if (!button) return false; button.click(); return true; })()`), { timeoutMs: 30_000, label: "文件 on app-shell" });
  await waitFor(() => main.evaluate("document.querySelector('[data-testid=\"docker-file-dialog\"]') !== null"), { label: "the file dialog" });
  const fileState = `(() => { const dialog = document.querySelector('[data-testid="docker-file-dialog"]'); return dialog ? { text: dialog.textContent, area: dialog.querySelector('textarea')?.value ?? null, error: dialog.querySelector('[role="alert"]')?.textContent ?? null, receipt: dialog.querySelector('[data-testid="docker-file-receipt"]')?.textContent ?? null, execute: dialog.querySelector('[data-testid="docker-file-execute"]') !== null, busy: dialog.querySelector('footer button')?.disabled === true } : null; })()`;
  const untilFile = (predicate, label, timeoutMs = 60_000) => waitFor(async () => { const value = await main.evaluate(fileState); return value !== null && predicate(value) ? value : null; }, { timeoutMs, label });
  const setValue = (selector, value) => main.evaluate(`(() => { const element = document.querySelector(${JSON.stringify(selector)}); const prototype = element instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : element instanceof HTMLSelectElement ? HTMLSelectElement.prototype : HTMLInputElement.prototype; Object.getOwnPropertyDescriptor(prototype, 'value').set.call(element, ${JSON.stringify(value)}); element.dispatchEvent(new Event(element instanceof HTMLSelectElement ? 'change' : 'input', { bubbles: true })); return true; })()`);
  const clickInDialogScript = (text) => clickText('[data-testid="docker-file-dialog"] button', text);
  const clickInDialog = (text) => main.evaluate(clickInDialogScript(text));

  // It opens on 浏览, at the container's root, already listed.
  // (An empty list is not an answer yet: `[]` would end the wait while the
  // root is still being listed.)
  const rootListed = await waitFor(() => main.evaluate("(() => { const names = [...document.querySelectorAll('[data-testid=\"docker-file-dialog\"] [data-testid=\"exec-browser-enter\"]')].map((button) => button.textContent); return names.length > 0 ? names : null; })()"), { timeoutMs: 60_000, label: "the browsed root" })
    .catch(() => null);
  check("the file dialog opens on browsing, with the container's root listed", rootListed?.includes("etc") === true && rootListed.includes("tmp"), rootListed);
  // Browse to the scratch file by the path bar and open it from its own row.
  await setValue('[data-testid="docker-file-dialog"] [data-testid="exec-browser-path"]', "/tmp");
  await waitFor(() => main.evaluate(clickInDialogScript("前往")), { label: "前往" });
  const scratchRow = `[...document.querySelectorAll('[data-testid="docker-file-dialog"] .exec-browser-table tbody tr')].find((row) => row.querySelector('.exec-browser-name')?.textContent === ${JSON.stringify(scratchName)})`;
  await waitFor(() => main.evaluate(`(${scratchRow}) != null`), { label: "the scratch file in /tmp" });
  await main.evaluate(`(${scratchRow}).querySelector('[data-testid="docker-browser-open"]').click(), true`);
  let file = await untilFile((value) => value.area !== null && !value.busy, "the file opened from its row");
  check("a file picked while browsing opens in the editor with its exact text", file.area === original, { area: file.area, original });
  await main.screenshot(path.join(evidence, "docker-file-browse-open.png"));

  // A typed path still works, and a missing file says so in plain words.
  await setValue('[data-testid="docker-file-dialog"] .docker-file-row input', "/tmp/does-not-exist-" + fileId);
  await clickInDialog("打开");
  file = await untilFile((value) => value.error !== null, "the missing-file refusal");
  check("opening a file that is not there says so in plain words", file.error === "这个文件不存在。", file.error);
  await setValue('[data-testid="docker-file-dialog"] .docker-file-row input', scratch);
  await clickInDialog("打开");
  file = await untilFile((value) => value.area !== null && value.error === null && !value.busy, "the opened file");
  check("a file inside the container opens with its exact text", file.area === original, { area: file.area, original });
  const edited = `${original}upstream=lovelyhawk\n`;
  await setValue('[data-testid="docker-file-dialog"] textarea', edited);
  await clickInDialog("保存");
  file = await untilFile((value) => value.execute, "the write plan");
  check("saving shows a plan naming the file and its current size before anything is written", file.text.includes(scratch) && file.text.includes("文件现为") && inApp(`cat ${scratch}`) === original, file.text.slice(0, 200));
  await main.screenshot(path.join(evidence, "docker-file-plan.png"));
  await main.evaluate("document.querySelector('[data-testid=\"docker-file-execute\"]').click(), true");
  file = await untilFile((value) => value.receipt !== null, "the write receipt");
  check("the write is read back inside the container and matches", file.receipt.includes("已完成，并在目标上核对过。") && file.receipt.includes("完全一致") && inApp(`cat ${scratch}`) === edited, { receipt: file.receipt.slice(0, 160) });

  // Changed in the container after it was opened: the save is refused, nothing is overwritten.
  await setValue('[data-testid="docker-file-dialog"] .docker-file-row input', scratch);
  await clickInDialog("打开");
  await untilFile((value) => value.area === edited && !value.busy, "the reopened file");
  inApp(`printf 'changed inside\\n' >> ${scratch}`);
  const changedInside = inApp(`cat ${scratch}`);
  await setValue('[data-testid="docker-file-dialog"] textarea', `${edited}operator edit\n`);
  await clickInDialog("保存");
  file = await untilFile((value) => value.error !== null, "the refused save");
  check("a save is refused when the file changed after it was opened, and the file is untouched", file.error === "文件在打开之后被改过了，请重新打开再改。" && inApp(`cat ${scratch}`) === changedInside, file.error);

  // Closing with an unsaved edit asks first.
  await clickInDialog("关闭");
  const ask = await waitFor(() => main.evaluate("document.querySelector('.dialog-host')?.textContent ?? null"), { label: "the discard question" }).catch(() => null);
  check("closing with an unsaved edit asks first", ask?.includes("放弃未保存的修改") === true, ask);
  await main.evaluate(clickText(".dialog-host button", "取消"));
  await delay(300);

  // Copy from the container to the machine it runs on.
  await clickInDialog("复制文件");
  await setValue('[data-testid="docker-file-dialog"] select', "container-to-host");
  const inputs = await main.evaluate("[...document.querySelectorAll('[data-testid=\"docker-file-dialog\"] .docker-file-copy input')].length");
  await main.evaluate(`(() => { const [from, to] = document.querySelectorAll('[data-testid="docker-file-dialog"] .docker-file-copy input'); for (const [element, value] of [[from, ${JSON.stringify(scratch)}], [to, ${JSON.stringify(copied)}]]) { Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(element, value); element.dispatchEvent(new Event('input', { bubbles: true })); } return true; })()`);
  await clickInDialog("生成计划");
  file = await untilFile((value) => value.execute, "the copy plan");
  check("a copy shows its plan, naming both ends", inputs === 2 && file.text.includes(scratch) && file.text.includes(copied) && onDockerHost(`test -e ${copied} && echo yes || echo no`).trim() === "no", file.text.slice(0, 200));
  await main.evaluate("document.querySelector('[data-testid=\"docker-file-execute\"]').click(), true");
  file = await untilFile((value) => value.receipt !== null, "the copy receipt");
  check("the copy lands on the host with the container's exact bytes", file.receipt.includes("已完成，并在目标上核对过。") && onDockerHost(`cat ${copied}`) === changedInside, file.receipt.slice(0, 160));
  await main.screenshot(path.join(evidence, "docker-file-copy.png"));
  await clickInDialog("关闭");
  await waitFor(() => main.evaluate("document.querySelector('.dialog-host') !== null ? (document.querySelector('.dialog-host button:last-child').click(), false) : document.querySelector('[data-testid=\"docker-file-dialog\"]') === null"), { timeoutMs: 10_000, label: "the file dialog to close" }).catch(() => undefined);

  // A shell inside app-shell, in its own window.
  await filterTo("app-shell");
  await waitFor(() => main.evaluate(`(() => { const button = (${rowOf("app-shell")})?.querySelector('[data-testid="docker-open-terminal"]'); if (!button) return false; button.click(); return true; })()`), { timeoutMs: 30_000, label: "终端 on app-shell" });
  const { session: shell } = await attach(port, (url) => url.includes("/terminal.html?window=container"), 30_000);
  await shell.send("Runtime.enable");
  await waitFor(() => shell.evaluate("(document.querySelector('.xterm-rows')?.textContent ?? '').trim().length > 0"), { timeoutMs: 60_000, label: "the container shell" });
  const marker = `docker-${randomUUID().slice(0, 8)}`;
  await shell.evaluate("document.querySelector('.xterm-helper-textarea')?.focus(), true");
  for (const character of `echo ${marker} $(cat /etc/debian_version >/dev/null && echo debian) $0`) {
    await shell.send("Input.dispatchKeyEvent", { type: "keyDown", key: character, text: character, unmodifiedText: character });
    await shell.send("Input.dispatchKeyEvent", { type: "keyUp", key: character });
  }
  await shell.send("Input.dispatchKeyEvent", { type: "keyDown", key: "Enter", code: "Enter", windowsVirtualKeyCode: 13, text: "\r" });
  await shell.send("Input.dispatchKeyEvent", { type: "keyUp", key: "Enter", code: "Enter", windowsVirtualKeyCode: 13 });
  const echoed = await waitFor(() => shell.evaluate(`(() => { const text = document.querySelector('.xterm-rows')?.textContent ?? ''; const at = text.lastIndexOf(${JSON.stringify(`${marker} debian`)}); return at >= 0 ? text.slice(at, at + 60) : null; })()`), { timeoutMs: 20_000, label: "the echo" }).catch(() => null);
  check("the container terminal runs inside app-shell, with bash", echoed !== null && /bash/u.test(echoed), echoed);
  const label = await shell.evaluate("document.documentElement.dataset.targetLabel ?? ''");
  check("the container terminal window names the container", label.includes("app-shell"), label);
  // The host's files beside a container's shell would read as the container's,
  // and opening a browser here would cut off the SSH window's own.
  const filePane = await shell.evaluate("({ toggle: document.querySelector('[data-testid=\"toggle-remote-files\"]') !== null, pane: document.querySelector('.ssh-window-files') !== null, note: document.querySelector('[data-testid=\"terminal-files-note\"]')?.textContent ?? null })");
  check("the container window shows no host file pane, and says where the host's files are", !filePane.toggle && !filePane.pane && filePane.note === "主机文件在 SSH 终端窗口的文件管理中", filePane);
  await shell.screenshot(path.join(evidence, "container-terminal.png"));

  // One window per container: the same container again reuses it, another opens its own.
  const terminalWindows = async () => (await listTargets(port)).filter((entry) => entry.url.includes("/terminal.html?window=container"));
  await main.evaluate(`(() => { const button = (${rowOf("app-shell")})?.querySelector('[data-testid="docker-open-terminal"]'); button?.click(); return true; })()`);
  await delay(2_000);
  check("opening app-shell's terminal again reuses its window", (await terminalWindows()).length === 1, (await terminalWindows()).length);
  await filterTo("incident-collector");
  await waitFor(() => main.evaluate(`(() => { const button = (${rowOf("incident-collector")})?.querySelector('[data-testid="docker-open-terminal"]'); if (!button) return false; button.click(); return true; })()`), { timeoutMs: 30_000, label: "终端 on incident-collector" });
  await waitFor(async () => (await terminalWindows()).length === 2, { timeoutMs: 30_000, label: "a second terminal window" }).catch(() => undefined);
  const windows = await terminalWindows();
  let second = null;
  // Both windows load the same page, so each is reached by its own debugger address.
  for (const entry of windows) {
    const session = await CdpSession.connect(entry.webSocketDebuggerUrl).catch(() => null);
    if (session === null) continue;
    const name = await session.evaluate("document.documentElement.dataset.targetLabel ?? ''").catch(() => "");
    if (name.includes("incident-collector")) second = session;
  }
  check("another container gets a window of its own, named for it", windows.length === 2 && second !== null, windows.length);
  if (second !== null) {
    await second.send("Runtime.enable");
    await waitFor(() => second.evaluate("(document.querySelector('.xterm-rows')?.textContent ?? '').trim().length > 0"), { timeoutMs: 60_000, label: "the second shell" });
    const marker2 = `alpine-${randomUUID().slice(0, 8)}`;
    await second.evaluate("document.querySelector('.xterm-helper-textarea')?.focus(), true");
    for (const character of `echo ${marker2} $(cat /etc/alpine-release >/dev/null && echo alpine)`) {
      await second.send("Input.dispatchKeyEvent", { type: "keyDown", key: character, text: character, unmodifiedText: character });
      await second.send("Input.dispatchKeyEvent", { type: "keyUp", key: character });
    }
    await second.send("Input.dispatchKeyEvent", { type: "keyDown", key: "Enter", code: "Enter", windowsVirtualKeyCode: 13, text: "\r" });
    await second.send("Input.dispatchKeyEvent", { type: "keyUp", key: "Enter", code: "Enter", windowsVirtualKeyCode: 13 });
    const echoed2 = await waitFor(() => second.evaluate(`(document.querySelector('.xterm-rows')?.textContent ?? '').includes(${JSON.stringify(`${marker2} alpine`)})`), { timeoutMs: 20_000, label: "the second echo" }).catch(() => false);
    check("the second window's shell runs inside incident-collector (Alpine, no bash)", echoed2 === true);
    // Something still running when the window goes away: closing must end it.
    for (const character of `sleep ${sleepSeconds}`) {
      await second.send("Input.dispatchKeyEvent", { type: "keyDown", key: character, text: character, unmodifiedText: character });
      await second.send("Input.dispatchKeyEvent", { type: "keyUp", key: character });
    }
    await second.send("Input.dispatchKeyEvent", { type: "keyDown", key: "Enter", code: "Enter", windowsVirtualKeyCode: 13, text: "\r" });
    await second.send("Input.dispatchKeyEvent", { type: "keyUp", key: "Enter", code: "Enter", windowsVirtualKeyCode: 13 });
    await delay(1_500);
  }
  const sleeping = () => execFileSync("wsl.exe", ["-d", "Ubuntu", "-u", "root", "-e", "docker", "exec", "svc-docker", "docker", "exec", "incident-collector", "sh", "-c", `ps -o args | grep -c '^sleep ${sleepSeconds}$' || true`], { encoding: "utf8" }).trim();
  check("the command started in the container shell is running", sleeping() === "1", sleeping());

  // Disconnect empties the page and closes the container window.
  await main.evaluate("document.querySelector('[data-testid=\"sidebar-disconnect-target\"]').click(), true");
  await waitFor(() => main.evaluate("document.querySelector('[data-testid=\"sidebar-disconnect-target\"]') === null"), { timeoutMs: 20_000, label: "the disconnect" });
  const after = await waitFor(() => main.evaluate("document.querySelectorAll('.docker-page tbody tr').length === 0 ? (document.querySelector('.docker-page, main')?.textContent ?? '') : null"), { timeoutMs: 15_000, label: "the emptied page" }).catch(() => null);
  check("after disconnecting nothing from the daemon remains on the page", after !== null && !after.includes("legacy-agent"), after?.slice(0, 120));
  await waitFor(async () => (await terminalWindows()).length === 0, { timeoutMs: 15_000, label: "the container windows to close" }).catch(() => undefined);
  check("disconnecting closes both container terminal windows", (await terminalWindows()).length === 0, (await terminalWindows()).length);
  await waitFor(() => sleeping() === "0", { timeoutMs: 15_000, label: "the sleep to end" }).catch(() => undefined);
  check("closing the window ended the command it was running in the container", sleeping() === "0", sleeping());
  check("no console errors in the main window", errors.length === 0, errors.slice(0, 3));
  await main.evaluate("document.querySelector('[data-testid=\"window-close\"]').click(), true");
  await waitFor(() => exitCode !== null, { timeoutMs: 15_000, label: "exit" }).catch(() => undefined);
  check("the app exits cleanly", exitCode === 0, exitCode);
} catch (error) {
  check("probe completed", false, error instanceof Error ? error.message : String(error));
  // What was on screen when it stopped, so a failure can be read, not re-run.
  try {
    await mainSession?.screenshot(path.join(evidence, "failure.png"));
    console.error(await mainSession?.evaluate("[...document.querySelectorAll('[role=dialog]')].map((dialog) => dialog.innerText).join(' --- ')"));
  } catch {}
  console.error(output.join("").slice(-3_000));
} finally {
  if (exitCode === null) child.kill();
  check("stopped-worker and stopped-batch are left stopped, as planted", !running("stopped-worker") && !running("stopped-batch"));
  // The scratch file, the write's backup beside it, and the copy — by exact names.
  inApp(`rm -f ${scratch} /tmp/.${scratchName}.lovelyres.*`);
  onDockerHost(`rm -f ${copied}`);
  check("the scratch files were removed", inApp(`ls -a /tmp | grep -c '${fileId}' || true`).trim() === "0" && onDockerHost(`test -e ${copied} && echo yes || echo no`).trim() === "no");
}

const failed = checks.filter((entry) => !entry.ok);
fs.writeFileSync(path.join(evidence, "report.json"), `${JSON.stringify({
  schema: "lovelyhawk-docker-probe/v1",
  status: failed.length === 0 ? "PASS" : "FAIL",
  generatedAt: new Date().toISOString(),
  checks,
}, null, 2)}\n`);
console.log(`${failed.length === 0 ? "PASS" : "FAIL"}: ${checks.length - failed.length}/${checks.length}; evidence in ${evidence}`);
process.exitCode = failed.length === 0 ? 0 : 1;
