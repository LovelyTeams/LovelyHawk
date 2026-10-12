// Real SFTP/RPC and the native desktop app over CDP. Only the OS directory
// picker is answered, through the debug build's scripted dialog answers; product IPC and reads are real.
import { execFileSync, spawn } from "node:child_process";
import { randomUUID, createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { inspectHtmlFile, startDesktop } from "./desktop.mjs";
import { Sidecar, connect } from "./rpc-harness.mjs";

const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const distro = process.env.EVIDENCE_LAB ?? "ubuntu";
if (!["ubuntu", "alpine"].includes(distro)) throw new Error("Choose ubuntu or alpine");
const runId = randomUUID(), name = `lr-file-evidence-${runId.slice(0, 8)}`;
const evidence = path.join(repository, "target/lab-file-evidence", runId);
const exportsRoot = path.join(evidence, "exports"); fs.mkdirSync(exportsRoot, { recursive: true });
const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "lovelyhawk-file-evidence-"));
const checks = [], consoleErrors = [];
const sample = Buffer.concat([Buffer.from("synthetic-private-evidence-token\u0000"), Buffer.from(Array.from({ length: 196627 }, (_, i) => i % 256))]);
const digest = createHash("sha256").update(sample).digest("hex");
let containerId, imageId, version, sidecar, app, session, failure;
const keepalive = spawn("wsl.exe", ["-d", "Ubuntu", "-u", "root", "--", "cat"], { windowsHide: true, stdio: ["pipe", "ignore", "ignore"] });
keepalive.once("error", (error) => { failure ??= String(error); });
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
function check(label, actual) { checks.push({ label, passed: Boolean(actual) }); console.log(`${actual ? "PASS" : "FAIL"} ${label}`); if (!actual) throw new Error(label); }
function wsl(...args) { return execFileSync("wsl.exe", ["-d", "Ubuntu", "-u", "root", "--", ...args], { encoding: "utf8", windowsHide: true, timeout: 60_000, maxBuffer: 2 * 1024 * 1024 }).trim(); }
const docker = (...args) => wsl("docker", ...args);
function owned() {
  const current = JSON.parse(docker("inspect", containerId))[0];
  if (current.Id !== containerId || current.Image !== imageId || current.Name !== `/${name}` || current.Config.Labels?.["lovelyres-test-run"] !== runId ||
    current.HostConfig.Privileged || current.Mounts.length !== 0 || current.HostConfig.NetworkMode !== "bridge") throw new Error("Fixture identity changed");
  return current;
}
const onHost = (...args) => { owned(); return docker("exec", containerId, ...args); };
async function until(fn, label, timeout = 60_000) { const end = Date.now() + timeout; while (Date.now() < end) { if (await fn()) return; await sleep(150); } throw new Error(`Timed out: ${label}`); }
const click = (selector, text) => session.evaluate(`(() => { const button = [...document.querySelectorAll(${JSON.stringify(selector)})].find(e => e.textContent.includes(${JSON.stringify(text)}) && !e.disabled); if (!button) throw new Error('Control missing'); button.click(); })()`);
const uiWait = (expression, label) => until(() => session.evaluate(expression), label);
async function finish(binding, job) { let current = job; await until(async () => { current = await sidecar.call("emergency.file-evidence", { action: "poll", bindingHandle: binding, jobHandle: job.jobHandle }); return current.state !== "collecting"; }, "file collection", 120_000); return current; }
try {
  imageId = docker("image", "inspect", `lovelyres-lab:${distro}`, "--format", "{{.Id}}");
  const host = wsl("hostname", "-I").split(/\s+/u).find((ip) => /^172\.(1[6-9]|2\d|3[01])\./u.test(ip)); if (!host) throw new Error("Missing private WSL address");
  containerId = docker("run", "-d", "--name", name, "--label", `lovelyres-test-run=${runId}`, "--memory", "384m", "--cpus", "1", "--pids-limit", "128", "-p", `${host}::22`, imageId);
  check("owned fixture has no privileged access or host mounts", Boolean(owned()));
  const port = Number(owned().NetworkSettings.Ports["22/tcp"][0].HostPort);
  version = onHost("sh", "-c", "cat /etc/os-release; uname -m");
  owned(); execFileSync("wsl.exe", ["-d", "Ubuntu", "-u", "root", "--", "docker", "exec", "-i", containerId, "sh", "-c", "cat > /usr/local/bin/lr-evidence-one; cp /usr/local/bin/lr-evidence-one /usr/local/bin/lr-evidence-two; chmod 4700 /usr/local/bin/lr-evidence-one /usr/local/bin/lr-evidence-two"], { input: sample, windowsHide: true });
  sidecar = new Sidecar(path.join(repository, "target/debug/lovelyhawk-backend.exe"), dataRoot);
  const connected = await connect(sidecar, { host, port, username: "root", password: "LabRoot#2026", id: runId, name });
  const binding = connected.bindingHandle;
  const catalog = await sidecar.call("emergency-command.catalog.load", { bindingHandle: binding });
  const command = catalog.commands.find((c) => c.title === "SUID 可执行"); check("real incident catalog offers SUID investigation", Boolean(command));
  const output = await sidecar.call("emergency-command.run", { bindingHandle: binding, snapshotHandle: catalog.snapshotHandle, commandHandle: command.commandHandle, containerHandle: null });
  const first = output.paths.find((p) => p.path === "/usr/local/bin/lr-evidence-one"), second = output.paths.find((p) => p.path === "/usr/local/bin/lr-evidence-two");
  check("real investigation issues owned file capabilities", Boolean(first && second));
  const begin = (offer) => sidecar.call("emergency.file-evidence", { action: "begin", bindingHandle: binding, pathHandle: offer.pathHandle, selectedDirectory: exportsRoot });
  const saved = await finish(binding, await begin(first));
  check("binary file collection completes with exact digest", saved.state === "completed" && saved.sha256 === digest && saved.totalBytes === sample.length);
  const folder = path.join(exportsRoot, saved.folderName), manifest = JSON.parse(fs.readFileSync(path.join(folder, "manifest.json"), "utf8"));
  check("raw sample remains byte-identical including invalid UTF-8", fs.readFileSync(path.join(folder, "sample.bin")).equals(sample));
  check("manifest identifies actual target, fingerprint, path, attributes and time", manifest.source.host === host && manifest.source.port === port && manifest.source.target.identity === runId && manifest.source.host_key_fingerprint.startsWith("SHA256:") &&
    manifest.observation.remote_path === first.path && manifest.observation.metadata.mode % 0o10000 === 0o4700 && manifest.observation.sha256 === digest && Boolean(manifest.observation.started_at && manifest.observation.completed_at));
  check("manifest retains collection limitations without copying sample secrets", manifest.limitations.includes("访问时间") && manifest.limitations.includes("原子快照") && !JSON.stringify(manifest).includes("synthetic-private-evidence-token"));
  const other = await finish(binding, await begin(second)); check("same bytes from another path get a distinct collection", other.state === "completed" && other.sha256 === digest && other.folderName !== saved.folderName);
  const report = await sidecar.call("disposal-report.generate", { bindingHandle: binding });
  check("evidence-only report includes two case records", report.incidentIncluded === true && report.evidenceCount === 2 && report.empty === false && report.summary.total === 0);
  for (const format of ["markdown", "html"]) {
    const content = await sidecar.call("disposal-report.content.get", { bindingHandle: binding, reportHandle: report.handle, format });
    check(`${format} retains both sources and raw-file hash scope`, content.content.includes(first.path) && content.content.includes(second.path) && content.content.includes(digest) && content.content.includes("external-artifact") && !content.content.includes("synthetic-private-evidence-token"));
    fs.writeFileSync(path.join(evidence, `evidence-report.${format === "markdown" ? "md" : "html"}`), content.content);
  }
  onHost("sh", "-c", "mv /usr/local/bin/lr-evidence-two /usr/local/bin/lr-evidence-two-original; ln -s /usr/local/bin/lr-evidence-one /usr/local/bin/lr-evidence-two");
  const symlink = await finish(binding, await begin(second));
  check("a path replaced by a symlink cannot publish a complete manifest", symlink.state === "failed" && !fs.existsSync(path.join(exportsRoot, symlink.folderName, "manifest.json")));
  onHost("sh", "-c", "rm /usr/local/bin/lr-evidence-two; mv /usr/local/bin/lr-evidence-two-original /usr/local/bin/lr-evidence-two; truncate -s 536870913 /usr/local/bin/lr-evidence-two");
  const oversized = await finish(binding, await begin(second)); check("oversized evidence rejected before copying bytes", oversized.state === "failed" && oversized.copiedBytes === 0);
  onHost("truncate", "-s", "268435456", "/usr/local/bin/lr-evidence-two");
  const started = await begin(second);
  const cancelled = await sidecar.call("emergency.file-evidence", { action: "cancel", bindingHandle: binding, jobHandle: started.jobHandle });
  await sleep(350);
  check("cancellation stops publication and does not add case evidence", cancelled.state === "cancelled" && !fs.existsSync(path.join(exportsRoot, started.folderName, "manifest.json"))) ;
  const after = await sidecar.call("disposal-report.generate", { bindingHandle: binding }); check("failed and cancelled captures stay out of completed evidence", after.evidenceCount === 2);
  onHost("sh", "-c", "cp /usr/local/bin/lr-evidence-one /usr/local/bin/lr-evidence-two; chmod 4700 /usr/local/bin/lr-evidence-two");
  sidecar.close(); sidecar = undefined; await sleep(300);
  if (distro === "ubuntu") {
    // The first directory choice is cancelled, the second chooses the exports
    // root. Changed in the Tauri port: the scripted answers cannot see which kind
    // of dialog asked, so "it was a directory picker" is shown instead by the
    // answers being consumed by exactly these clicks and the capture landing in that directory.
    app = await startDesktop({ dataRoot, evidence, dialogAnswers: [null, exportsRoot],
      onConsoleError: (entry) => consoleErrors.push(JSON.stringify({ ...entry.params, phase: entry.phase, source: entry.source })) });
    session = app.session;
    await uiWait("document.querySelector('.connection-card button') !== null", "connection card"); await session.evaluate("document.querySelector('.connection-card button').click()");
    await uiWait("document.querySelector('[data-testid=disconnect-target]:not([disabled])') !== null", "connected UI");
    await click(".nav-item", "命令工作台"); await uiWait("document.querySelector('.emergency-commands-list') !== null", "incident page");
    await click(".emergency-commands-list button", "SUID 可执行"); await click(".emergency-command-run", "运行只读调查");
    await uiWait("[...document.querySelectorAll('.emergency-path-open')].some(e=>e.getAttribute('aria-label').includes('/usr/local/bin/lr-evidence-one'))", "visible path controls");
    const open = async () => { await session.evaluate("[...document.querySelectorAll('.emergency-path-open')].find(e=>e.getAttribute('aria-label').includes('/usr/local/bin/lr-evidence-one')).click()"); await click(".emergency-path-menu button", "下载留证"); await uiWait("document.querySelector('.file-evidence-dialog') !== null", "evidence dialog"); };
    await open(); check("read-only evidence dialog starts on safe close control", await session.evaluate("document.activeElement?.textContent === '关闭'"));
    check("no directory was chosen before the operator asked", app.dialogAnswersLeft().length === 2);
    await session.shot("file-evidence-ready.png"); await click(".file-evidence-dialog footer button", "选择目录并留证");
    await uiWait("document.querySelector('.file-evidence-dialog footer .is-primary:not([disabled])') !== null", "picker cancellation returns to ready");
    check("the first choice was the cancelled directory dialog", JSON.stringify(app.dialogAnswersLeft()) === JSON.stringify([exportsRoot]));
    const foldersBefore = new Set(fs.readdirSync(exportsRoot));
    await click(".file-evidence-dialog footer button", "选择目录并留证");
    await uiWait("document.querySelector('.file-evidence-hash') !== null", "UI capture verified");
    check("the second choice was consumed and the capture landed in the chosen directory", app.dialogAnswersLeft().length === 0 && fs.readdirSync(exportsRoot).some((entry) => !foldersBefore.has(entry) && fs.existsSync(path.join(exportsRoot, entry, "manifest.json"))));
    check("native UI shows verified hash, source and case linkage", await session.evaluate(`document.querySelector('.file-evidence-hash').textContent === ${JSON.stringify(digest)} && document.querySelector('.file-evidence-dialog').textContent.includes('已关联') && document.querySelector('.file-evidence-dialog').textContent.includes(${JSON.stringify(`root@${host}:${port}`)})`));
    await session.send("Emulation.setDeviceMetricsOverride", { width: 1080, height: 700, deviceScaleFactor: 1, mobile: false });
    check("minimum window contains evidence dialog and controls", await session.evaluate("(()=>{const b=document.querySelector('.file-evidence-dialog').getBoundingClientRect(); return b.left>=0&&b.right<=innerWidth&&b.top>=0&&b.bottom<=innerHeight&&document.documentElement.scrollWidth<=innerWidth+1})()"));
    await session.shot("file-evidence-completed.png"); await click(".file-evidence-dialog footer button", "关闭");
    check("closing returns keyboard focus to the original file control", await session.evaluate("document.activeElement?.getAttribute('aria-label') === '文件操作：/usr/local/bin/lr-evidence-one'"));
    await session.evaluate("document.querySelector('[data-testid=open-disposal-report]').click()");
    await uiWait("document.querySelector('.disposal-report-evidence')?.textContent.includes('3 条证据')", "evidence report UI");
    await click(".disposal-report-body nav button", "Markdown");
    await uiWait(`document.querySelector('.disposal-report-preview pre')?.textContent.includes(${JSON.stringify(digest)})`, "report hash");
    await session.shot("file-evidence-report.png");
    // Changed in the Tauri port: there is no hidden window to render the export, so it is parsed inertly in the page; layout overflow and the rendered screenshot are no longer observed.
    const standalone = await inspectHtmlFile(session, path.join(evidence, "evidence-report.html"),
      "(d) => ({ details: d.querySelectorAll('.evidence-detail').length, activeContent: d.querySelector('script,iframe,img') !== null })");
    check("standalone HTML preserves both evidence details without active content", standalone.details === 2 && !standalone.activeContent);
    check("desktop console has no errors", consoleErrors.length === 0);
  }
} catch (error) {
  failure = String(error); console.error(failure); process.exitCode = 1;
  if (session) { try { await session.shot("failure.png"); fs.writeFileSync(path.join(evidence, "failure-text.txt"), await session.evaluate("document.body.innerText")); } catch {} }
} finally {
  sidecar?.close();
  if (app) await app.close();
  if (containerId) { try { owned(); docker("rm", "-f", containerId); check("owned container removed", true); } catch (error) { failure ??= String(error); process.exitCode = 1; } }
  try {
    const resolved = fs.realpathSync(dataRoot), temp = fs.realpathSync(os.tmpdir());
    if (path.dirname(resolved) !== temp || !/^lovelyhawk-file-evidence-[A-Za-z0-9]{6}$/u.test(path.basename(resolved))) throw new Error("Unexpected test data directory");
    fs.rmSync(resolved, { recursive: true, maxRetries: 10, retryDelay: 300 }); check("isolated app data removed", true);
  } catch (error) { failure ??= String(error); process.exitCode = 1; }
  fs.writeFileSync(path.join(evidence, "report.json"), JSON.stringify({ runId, date: new Date().toISOString(), distro, imageId, version, checks, consoleErrors, error: failure ?? null,
    limits: ["native OS directory picker alone is answered through the debug build's scripted dialog answers, which cannot tell a directory picker from another dialog", "exported HTML is parsed inertly in the app page; its rendered layout and screenshot are not captured (the Tauri host has no hidden window)", "SFTP double observation is not an atomic filesystem snapshot", "container userland evidence does not establish complete distribution support"] }, null, 2));
  console.log(`Evidence: ${path.join(evidence, "report.json")}`); keepalive.stdin.end();
}
