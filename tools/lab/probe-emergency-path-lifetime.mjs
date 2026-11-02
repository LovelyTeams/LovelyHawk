// Real SSH/SFTP and native WebView2 regression for file entries from group runs.
// Only a newly created, identity-checked container and private app data are used.
import { execFileSync, spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Sidecar, backendBinary, connect } from "./rpc-harness.mjs";
import { startDesktop, waitFor } from "./desktop.mjs";

const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const runId = randomUUID(), name = `lh-path-lifetime-${runId.slice(0, 8)}`;
const evidence = path.join(repository, "target/lab-emergency-path-lifetime", runId);
const dataRoot = path.join(evidence, "app"), exportsRoot = path.join(evidence, "exports");
const channelRegressions = process.argv.includes("--channel-regressions");
const measureLatency = process.argv.includes("--latency") || channelRegressions;
fs.mkdirSync(dataRoot, { recursive: true }); fs.mkdirSync(exportsRoot);
const report = { runId, startedAt: new Date().toISOString(), checks: [], errors: [], timings: [],
  sftpChannelStartupDelayMs: measureLatency ? 250 : 0,
  scope: "Debian amd64 container via real SSH/SFTP and native debug WebView2; not VM/kernel or container-internal file-action acceptance" };
const keepalive = spawn("wsl.exe", ["-d", "Ubuntu", "-u", "root", "--", "cat"], { windowsHide: true, stdio: ["pipe", "ignore", "ignore"] });
const wsl = (...args) => execFileSync("wsl.exe", ["-d", "Ubuntu", "-u", "root", "--", ...args],
  { encoding: "utf8", windowsHide: true, timeout: 120_000, maxBuffer: 2 * 1024 * 1024 }).trim();
const docker = (...args) => wsl("docker", ...args);
const planted = "/usr/local/bin/lh-path-lifetime-marker";
let containerId, imageId, sidecar, app;
function owned() {
  const target = JSON.parse(docker("inspect", containerId))[0];
  if (target.Id !== containerId || target.Image !== imageId || target.Name !== `/${name}` ||
    target.Config.Labels?.["lovelyhawk-test-run"] !== runId || target.HostConfig.Privileged ||
    target.HostConfig.NetworkMode !== "bridge" || target.Mounts.length !== 0 ||
    target.HostConfig.Memory !== 256 * 1024 * 1024 || target.HostConfig.PidsLimit !== 256) throw new Error("Lab identity or isolation changed");
  return target;
}
function onHost(...args) { owned(); return docker("exec", containerId, ...args); }
function check(label, passed, detail) {
  report.checks.push({ label, passed: Boolean(passed), detail });
  console.log(`${passed ? "PASS" : "FAIL"} ${label}`);
  if (!passed) throw new Error(label);
}
async function timed(label, operation) {
  const started = performance.now();
  try { return await operation(); }
  finally { report.timings.push({ label, elapsedMs: Math.round(performance.now() - started) }); }
}
async function refused(label, operation, code) {
  let message;
  try { await operation(); } catch (error) { message = String(error.message); }
  check(label, message?.startsWith(`${code}:`) === true, message);
}
const mode = () => onHost("stat", "-c", "%a", planted);
const channelCount = () => Number(onHost("sh", "-c", "wc -l < /tmp/lh-sftp-opens"));
const sftpProcesses = () => onHost("ps", "-eo", "pid=,stat=,comm=").split("\n")
  .map(line => line.trim().split(/\s+/u)).filter(([, , name]) => name === "sftp-server")
  .map(([pid, state]) => ({ pid, state }));
function writeFixtureFile(destination, content) {
  owned();
  execFileSync("wsl.exe", ["-d", "Ubuntu", "-u", "root", "--", "docker", "exec", "-i", containerId,
    "tee", destination], { input: content, windowsHide: true, timeout: 10_000, stdio: ["pipe", "ignore", "pipe"] });
}
try {
  imageId = docker("image", "inspect", "lovelyres-svc:baseline-deb", "--format", "{{.Id}}");
  const host = wsl("hostname", "-I").split(/\s+/u).find(ip => /^172\.(1[6-9]|2\d|3[01])\./u.test(ip));
  if (!host) throw new Error("No private WSL address");
  containerId = docker("run", "-d", "--name", name, "--label", `lovelyhawk-test-run=${runId}`,
    "--memory", "256m", "--cpus", "1", "--pids-limit", "256", "-p", `${host}::22`, imageId);
  const target = owned(), port = Number(target.NetworkSettings.Ports["22/tcp"][0].HostPort);
  report.target = { id: target.Id, name: target.Name, image: target.Image, network: target.HostConfig.NetworkMode, mounts: target.Mounts };
  report.environment = onHost("sh", "-c", "cat /etc/os-release; uname -m; /usr/sbin/sshd -V 2>&1");
  // Harmless text marker: it is listed by permissions, never executed.
  onHost("sh", "-c", `printf 'LovelyHawk path lifetime fixture\\n' > ${planted}; chmod 4755 ${planted}`);
  if (measureLatency) {
    // Simulate a slow subsystem startup (not a slow disk or network), and count
    // actual SFTP channel opens independently of the client implementation.
    writeFixtureFile("/usr/local/bin/lh-probe-sftp",
      "#!/bin/sh\nprintf 'open\\n' >> /tmp/lh-sftp-opens\nsleep 0.25\nexec /usr/lib/openssh/sftp-server\n");
    onHost("chmod", "755", "/usr/local/bin/lh-probe-sftp");
    onHost("sh", "-c", "sed -i 's@^Subsystem[[:space:]].*@Subsystem sftp /usr/local/bin/lh-probe-sftp@' /etc/ssh/sshd_config; /usr/sbin/sshd -t");
    const sshdPid = onHost("pgrep", "-xo", "sshd");
    if (!/^[1-9][0-9]*$/u.test(sshdPid)) throw new Error("Expected the fixture SSH listener PID");
    onHost("kill", "-HUP", sshdPid);
  }
  sidecar = new Sidecar(backendBinary(), dataRoot);
  const connected = await connect(sidecar, { host, port, username: "root", password: "LabRoot#2026", id: runId, name });
  check("owned SSH target connected", connected.stage === "connected");
  const bindingHandle = connected.bindingHandle;
  const call = (method, rest = {}) => timed(`rpc:${method}`, () => sidecar.call(method, { bindingHandle, ...rest }, 180_000));
  const catalog = await call("emergency-command.catalog.load");
  const suid = catalog.commands.find(command => command.title === "SUID 可执行");
  const sgid = catalog.commands.find(command => command.title === "SGID 可执行");
  check("catalog offers two independent permission checks", suid && sgid);
  const run = command => call("emergency-command.run", { snapshotHandle: catalog.snapshotHandle, commandHandle: command.commandHandle });
  const first = await run(suid);
  const offer = first.paths.find(entry => entry.path === planted);
  check("first command offers the exact planted file", offer && first.output.split("\n")[offer.line] === planted);
  await run(sgid);
  const inspect = () => call("emergency-command.path.inspect", { pathHandle: offer.pathHandle });
  const detail = await inspect();
  check("earlier group entry survives the next command", detail.path === planted && detail.mode === "4755");
  check("viewing properties does not consume the file entry", (await inspect()).pathHandle === offer.pathHandle);
  await refused("forged file entry is refused", () => call("emergency-command.path.inspect", { pathHandle: randomUUID() }), "emergency-path-unavailable");
  const plan = await call("emergency-command.path.plan", { pathHandle: offer.pathHandle, action: "disarm" });
  await refused("unconfirmed mutation cannot execute", () => call("emergency-command.path.execute", { planHandle: plan.planHandle }), "emergency-path-plan-unavailable");
  await run(sgid);
  await call("emergency-command.path.confirm", { planHandle: plan.planHandle });
  const receipt = await call("emergency-command.path.execute", { planHandle: plan.planHandle });
  check("original file entry plans, confirms and executes after later checks", receipt.passed && receipt.undoable && mode() === "644");
  await refused("mutation plan remains single use", () => call("emergency-command.path.execute", { planHandle: plan.planHandle }), "emergency-path-plan-unavailable");
  check("spent plan does not consume the read-only file entry", (await inspect()).mode === "0644");
  const undone = await call("emergency-command.path.undo", { planHandle: plan.planHandle });
  check("undo independently restores the exact original permissions", undone.undone && mode() === "4755");
  await refused("undo remains single use", () => call("emergency-command.path.undo", { planHandle: plan.planHandle }), "emergency-path-plan-unavailable");
  const changed = await call("emergency-command.path.plan", { pathHandle: offer.pathHandle, action: "disarm" });
  await call("emergency-command.path.confirm", { planHandle: changed.planHandle });
  onHost("chmod", "4700", planted);
  const refusedChange = await call("emergency-command.path.execute", { planHandle: changed.planHandle });
  check("file changed after confirmation is left untouched", refusedChange.untouched && !refusedChange.passed && mode() === "4700");
  onHost("chmod", "4755", planted);
  if (channelRegressions) {
    const before = channelCount();
    check("reused channel still reads current remote permissions", (await inspect()).mode === "4755");
    check("repeated inspection reuses the same channel", channelCount() === before);
    const broken = await call("emergency-command.path.plan", { pathHandle: offer.pathHandle, action: "disarm" });
    await call("emergency-command.path.confirm", { planHandle: broken.planHandle });
    const pids = sftpProcesses().filter(process => !process.state.startsWith("Z")).map(process => process.pid);
    if (pids.length !== 1 || !/^[1-9][0-9]*$/u.test(pids[0])) throw new Error("Expected one owned idle SFTP channel");
    onHost("kill", "-TERM", pids[0]);
    const failed = await call("emergency-command.path.execute", { planHandle: broken.planHandle });
    check("broken transport does not replay a mutation", !failed.passed && mode() === "4755" && channelCount() === before);
    check("next independent read opens a fresh channel", (await inspect()).mode === "4755" && channelCount() === before + 1);
    await call("ssh.binding.disconnect");
    // The fixture's sleep PID 1 does not reap every orphan. An exited zombie
    // has no open channel; retain its state instead of treating its PID as live.
    let remaining;
    await waitFor(() => {
      report.afterDisconnectSftpProcesses = sftpProcesses();
      remaining = report.afterDisconnectSftpProcesses.filter(process => !process.state.startsWith("Z"));
      return remaining.length === 0;
    },
      { timeoutMs: 10_000, label: "idle SFTP channel released on disconnect" });
    check("disconnect releases the cached remote subsystem", remaining.length === 0);
    writeFixtureFile("/usr/local/bin/find", '#!/bin/sh\nfor argument in "$@"; do\n  if [ "$argument" = "-2000" ]; then\n    : > /tmp/lh-scan-started\n    sleep 8\n  fi\ndone\nexec /usr/bin/find "$@"\n');
    onHost("chmod", "755", "/usr/local/bin/find");
  }
  sidecar.close(); sidecar = undefined;

  app = await startDesktop({ dataRoot, evidence, dialogAnswers: channelRegressions ? [exportsRoot, exportsRoot] : [exportsRoot],
    onConsoleError: entry => report.errors.push(entry) });
  report.desktopObservedAt = new Date().toISOString();
  if (channelRegressions) {
    await app.recordHostCalls();
    report.hostCallsObservedAt = app.hostCallsSince;
  }
  const { session } = app;
  const wait = (expression, label) => waitFor(() => session.evaluate(expression), { timeoutMs: 180_000, label });
  const click = (selector, label) => session.evaluate(`(() => {
    const button = [...document.querySelectorAll(${JSON.stringify(selector)})].find(item => !item.disabled && item.textContent.includes(${JSON.stringify(label)}));
    if (!button) throw new Error('Enabled control missing'); button.click(); return true;
  })()`);
  await wait("document.querySelector('.connection-card button') !== null", "connection card");
  await session.evaluate("document.querySelector('.connection-card button').click(); true");
  await wait("document.querySelector('[data-testid=disconnect-target]:not([disabled])') !== null", "connected desktop");
  await click(".nav-item", "命令工作台");
  await wait("document.querySelector('.emergency-commands-list') !== null", "workbench");
  await session.evaluate(`(() => { const input = document.querySelector('[aria-label="搜索命令"]');
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(input, 'ID 可执行');
    input.dispatchEvent(new Event('input', {bubbles:true})); return true; })()`);
  await wait("document.querySelectorAll('.emergency-command-group-items button').length === 2", "two visible checks");
  await click(".emergency-command-group-run", "快速执行");
  if (!channelRegressions) await wait("document.querySelector('.emergency-command-progress')?.textContent.includes('已完成 2 项')", "native group finished");
  const fileControl = `[...document.querySelectorAll('.emergency-path-open')].find(item => item.getAttribute('aria-label') === ${JSON.stringify(`文件操作：${planted}`)})`;
  const open = async action => {
    await session.evaluate(`(() => { const item = ${fileControl}; if (!item) throw new Error('File entry missing');
      item.closest('details').open = true; item.click(); return true; })()`);
    await click(".emergency-path-menu button", action);
  };
  if (channelRegressions) {
    await waitFor(() => { try { onHost("test", "-f", "/tmp/lh-scan-started"); return true; } catch { return false; } },
      { timeoutMs: 10_000, label: "slow SGID scan started" });
    await timed("desktop:properties-during-scan", async () => {
      await open("查看属性");
      await wait("document.querySelector('[data-testid=emergency-path-properties] dl') !== null", "properties during scan");
    });
    check("file properties finish while investigation is still running", await session.evaluate(
      "globalThis.__lovelyhawkLabHostCalls.calls.some(call => call.method === 'emergency-command.run' && call.status === 'pending')"));
    await session.shot("file-properties-during-investigation.png");
    await click("[data-testid=emergency-path-properties] footer button", "关闭");
    await open("去掉执行权限");
    await wait("document.querySelector('[data-testid=emergency-path-execute]:not([disabled])') !== null", "plan during scan");
    check("file planning also finishes before the investigation", await session.evaluate(
      "globalThis.__lovelyhawkLabHostCalls.calls.some(call => call.method === 'emergency-command.run' && call.status === 'pending')"));
    await click("[data-testid=emergency-path-dialog] footer button", "取消");
    await open("下载留证");
    await wait("document.querySelector('.file-evidence-dialog') !== null", "evidence during scan");
    await click(".file-evidence-dialog footer button", "选择目录并留证");
    await wait("document.querySelector('.file-evidence-hash') !== null", "evidence finished during scan");
    check("evidence collection and progress are not blocked by investigation", await session.evaluate(
      "globalThis.__lovelyhawkLabHostCalls.calls.some(call => call.method === 'emergency-command.run' && call.status === 'pending')"));
    await session.shot("file-evidence-during-investigation.png");
    await click(".file-evidence-dialog footer button", "关闭");
    await wait("document.querySelector('.emergency-command-progress')?.textContent.includes('已完成 2 项')", "native group finished");
  }
  for (let attempt = 0; attempt < 2; attempt++) {
    await timed(`desktop:properties:${attempt + 1}`, async () => {
      await open("查看属性");
      await wait("document.querySelector('[data-testid=emergency-path-properties] dl') !== null", "earlier file properties");
    });
    check(`native earlier result properties open ${attempt + 1}`, await session.evaluate("document.querySelector('[data-testid=emergency-path-properties]').textContent.includes('4755')"));
    if (attempt === 0) await session.shot("earlier-group-file-properties.png");
    await click("[data-testid=emergency-path-properties] footer button", "关闭");
  }
  await timed("desktop:plan:first", async () => {
    await open("去掉执行权限");
    await wait("document.querySelector('[data-testid=emergency-path-execute]:not([disabled])') !== null", "first native plan");
  });
  await click("[data-testid=emergency-path-dialog] footer button", "取消");
  check("cancelling the native plan leaves the file intact", mode() === "4755");
  await timed("desktop:plan:again", async () => {
    await open("去掉执行权限");
    await wait("document.querySelector('[data-testid=emergency-path-execute]:not([disabled])') !== null", "new native plan");
  });
  await timed("desktop:execute-and-verify", async () => {
    await click("[data-testid=emergency-path-execute]", "确认并执行");
    await wait("document.querySelector('[data-testid=emergency-path-undo]') !== null", "verified native receipt");
  });
  check("native confirmation changed only the intended permissions", mode() === "644");
  await timed("desktop:undo-and-verify", async () => {
    await click("[data-testid=emergency-path-undo]", "撤销这次操作");
    await click("[data-testid=emergency-path-undo-confirm]", "确认撤销");
    await wait("document.querySelector('[data-testid=emergency-path-undo-result]') !== null", "native undo");
  });
  check("native undo verified the original permissions", mode() === "4755");
  await session.shot("earlier-group-file-action-undone.png");
  await click("[data-testid=emergency-path-dialog] footer button", "关闭");
  await open("下载留证");
  await wait("document.querySelector('.file-evidence-dialog') !== null", "evidence dialog");
  await click(".file-evidence-dialog footer button", "选择目录并留证");
  await wait("document.querySelector('.file-evidence-hash') !== null", "evidence collected");
  const saved = fs.readdirSync(exportsRoot).find(folder => fs.existsSync(path.join(exportsRoot, folder, "sample.bin")));
  check("same earlier result still supports evidence collection", saved && fs.readFileSync(path.join(exportsRoot, saved, "sample.bin"), "utf8") === "LovelyHawk path lifetime fixture\n");
  await session.shot("earlier-group-file-evidence.png");
  await click(".file-evidence-dialog footer button", "关闭");
  await session.evaluate("document.querySelector('[data-testid=disconnect-target]').click(); true");
  await wait("document.querySelector('.emergency-commands-disconnected') !== null", "disconnected workbench");
  check("disconnect removes file menus and dialogs", await session.evaluate("document.querySelector('.emergency-path-menu, .emergency-path-dialog, .file-evidence-dialog') === null"));
  check("native startup and runtime have no recorded errors", report.errors.length === 0);
  if (channelRegressions) report.hostCalls = await app.hostCalls();
  if (measureLatency) report.sftpChannelsOpened = channelCount();
} catch (error) {
  report.failure = String(error); console.error(error); process.exitCode = 1;
  if (app) { try { await app.session.shot("failure.png"); fs.writeFileSync(path.join(evidence, "failure-text.txt"), await app.session.evaluate("document.body.innerText")); } catch {} }
} finally {
  sidecar?.close();
  if (app) {
    fs.writeFileSync(path.join(evidence, "desktop-output.log"), app.output.join(""));
    try { await app.close(); }
    catch (error) { report.closeFailure = String(error); process.exitCode = 1; }
  }
  if (containerId) {
    try { owned(); docker("rm", "-f", containerId); report.cleanedUp = true; }
    catch (error) { report.cleanupFailure = String(error); process.exitCode = 1; }
  }
  report.completedAt = new Date().toISOString();
  fs.writeFileSync(path.join(evidence, "report.json"), JSON.stringify(report, null, 2));
  console.log(`Evidence: ${path.join(evidence, "report.json")}`);
  keepalive.stdin.end();
  keepalive.kill();
}
