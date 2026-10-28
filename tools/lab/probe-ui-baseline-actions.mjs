// Baseline changes and restores in the Tauri window against a real host:
// select a setting, read the plan in the in-app confirmation, approve it,
// see the receipt, then put the change back from history — checked on the
// host by what sshd itself reports.
//
// The host is a container this probe creates from the local
// lovelyres-svc:baseline-<deb|el> image (BASELINE=deb by default), labelled
// with this run's id, resource-limited, reachable only on the WSL address,
// and removed at the end after its identity is checked again.
//
//   BASELINE=el node tools/lab/probe-ui-baseline-actions.mjs
import { execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { startDesktop } from "./desktop.mjs";
import { Sidecar, backendBinary, connect } from "./rpc-harness.mjs";

const flavour = process.env.BASELINE ?? "deb";
if (!["deb", "el"].includes(flavour)) throw new Error(`Unknown BASELINE ${flavour}`);
const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const runId = randomUUID();
const name = `lr-ui-baseline-${flavour}-${runId.slice(0, 8)}`;
const evidence = path.join(repository, "target", "lab-ui-baseline-actions", flavour, runId);
const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "lovelyhawk-ui-baseline-"));
const config = "/etc/ssh/sshd_config";
const checks = [];
let failures = 0;
let containerId = null;
let imageId = null;
let app = null;
const consoleErrors = [];
fs.mkdirSync(evidence, { recursive: true });

/**
 * check(label, ok, detail) with a boolean, or check(label, actual, expected)
 * compared exactly. A value is never taken as a pass just for being truthy,
 * and a non-boolean with nothing to compare against fails rather than being
 * compared with a default (`check(label, null)` used to pass).
 */
function check(label, ok, ...rest) {
  const comparing = typeof ok !== "boolean";
  const detail = rest.length > 0 ? rest[0] : null;
  const passed = comparing ? rest.length > 0 && ok === detail : ok;
  const shown = comparing ? { actual: ok, expected: rest.length > 0 ? detail : "(nothing to compare with)" } : detail;
  checks.push({ label, passed, detail: shown });
  if (!passed) failures += 1;
  console.log(`${passed ? "PASS" : "FAIL"} ${label}${passed || shown === null ? "" : ` — ${JSON.stringify(shown).slice(0, 400)}`}`);
}
const wsl = (...args) => execFileSync("wsl.exe", ["-d", "Ubuntu", "-u", "root", "--", ...args],
  { encoding: "utf8", windowsHide: true, timeout: 120_000, maxBuffer: 4 * 1024 * 1024 }).trim();
const docker = (...args) => wsl("docker", ...args);
function owned() {
  const target = JSON.parse(docker("inspect", containerId))[0];
  if (target.Id !== containerId || target.Image !== imageId || target.Name !== `/${name}` ||
    target.Config.Labels?.["lovelyres-test-run"] !== runId || target.HostConfig.Privileged ||
    target.HostConfig.Memory !== 256 * 1024 * 1024 || target.HostConfig.PidsLimit !== 256) {
    throw new Error("The baseline fixture's identity or limits changed");
  }
  return target;
}
function script(input) {
  owned();
  return execFileSync("wsl.exe", ["-d", "Ubuntu", "-u", "root", "--", "docker", "exec", "-i", containerId, "sh", "-se"],
    { input, encoding: "utf8", windowsHide: true, timeout: 120_000 }).trim();
}
const digest = () => script(`sha256sum ${config} | awk '{print $1}'`);
const effective = (key) => script(`$(command -v sshd || echo /usr/sbin/sshd) -T 2>/dev/null | awk 'tolower($1)==tolower("${key}"){print $2; exit}'`);
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
async function until(predicate, label, timeoutMs = 60_000) {
  const end = Date.now() + timeoutMs;
  while (Date.now() < end) {
    try { if (await predicate()) return; } catch {}
    await sleep(300);
  }
  throw new Error(`Timed out: ${label}`);
}

try {
  imageId = docker("image", "inspect", `lovelyres-svc:baseline-${flavour}`, "--format", "{{.Id}}");
  const host = wsl("hostname", "-I").split(/\s+/u).find((ip) => /^172\.(1[6-9]|2\d|3[01])\.\d+\.\d+$/u.test(ip));
  if (!host) throw new Error("Missing private WSL address");
  containerId = docker("run", "-d", "--name", name, "--label", `lovelyres-test-run=${runId}`, "--memory", "256m",
    "--cpus", "1", "--pids-limit", "256", "-p", `${host}::22`, imageId);
  const sshPort = Number(owned().NetworkSettings.Ports["22/tcp"][0].HostPort);
  await until(() => script("pgrep -x sshd >/dev/null && echo up || echo down") === "up", "sshd in the fixture");
  const original = digest();

  // The setting's title, looked up the way the page shows it.
  const sidecar = new Sidecar(backendBinary(), dataRoot);
  let title = null;
  try {
    const status = await connect(sidecar, { host, port: sshPort, username: "root", password: "LabRoot#2026",
      id: "55555555-5555-4555-8555-555555555511", name: `基线靶机 ${flavour}` });
    if (status?.stage !== "connected") throw new Error(`fixture connect failed: ${JSON.stringify(status)}`);
    const catalog = await sidecar.call("baseline.catalog.get", {});
    const scan = await sidecar.call("baseline.scan", { bindingHandle: status.bindingHandle }, 120_000);
    const row = scan.statuses.find((item) => item.fix.lines.some((line) => line.startsWith("PermitRootLogin ")));
    title = catalog.items.find((item) => item.itemHandle === row.itemHandle).title;
    await sidecar.call("ssh.binding.disconnect", { bindingHandle: status.bindingHandle });
  } finally { sidecar.close(); }

  app = await startDesktop({ dataRoot, evidence,
    onConsoleError: (event) => consoleErrors.push(JSON.stringify(event.params ?? event).slice(0, 600)) });
  const page = app.session;
  const evaluate = (expression) => page.evaluate(expression);
  const uiWait = (expression, label, timeoutMs = 120_000) => until(async () => (await evaluate(expression)) === true, label, timeoutMs);
  await uiWait(`[...document.querySelectorAll('.connection-card')].some((card) => card.textContent.includes(${JSON.stringify(`基线靶机 ${flavour}`)}))`, "the connection card");
  await evaluate(`(() => { const card = [...document.querySelectorAll('.connection-card')].find((c) => c.textContent.includes(${JSON.stringify(`基线靶机 ${flavour}`)})); (card.querySelector('button') ?? card).click(); return true; })()`);
  await uiWait("document.querySelector('[data-testid=\"sidebar-disconnect-target\"]') !== null", "the connection");
  await evaluate("[...document.querySelectorAll('.nav-item')].find((n) => n.querySelector('strong')?.textContent === '配置')?.click(), true");
  await uiWait("[...document.querySelectorAll('.configuration-modes button')].some((b) => b.textContent.includes('检查这台主机'))", "the configuration page");
  await evaluate("[...document.querySelectorAll('.configuration-modes button')].find((b) => b.textContent.includes('检查这台主机')).click(), true");
  await uiWait("[...document.querySelectorAll('.baseline-view-header button')].some((b) => !b.disabled)", "the scan button");
  await evaluate("[...document.querySelectorAll('.baseline-view-header button')].find((b) => !b.disabled).click(), true");
  const card = `[...document.querySelectorAll('.baseline-card')].find((b) => b.querySelector('strong')?.textContent === ${JSON.stringify(title)})`;
  await uiWait(`(${card}) != null && !(${card}).textContent.includes('尚未扫描')`, "the scanned card");
  await evaluate(`(${card}).click(), true`);
  await uiWait("document.querySelector('[data-testid=\"baseline-change-plan\"]') !== null", "the change panel");
  check("the selected setting offers a change, the recommendation chosen",
    await evaluate("document.querySelector('[data-testid=\"baseline-change-value\"]').value") === "no");
  await page.shot("baseline-change-panel.png");

  // Change: the plan in the confirmation, then approve.
  await evaluate("document.querySelector('[data-testid=\"baseline-change-plan\"]').click(), true");
  await uiWait("document.querySelector('[role=dialog]') !== null", "the confirmation");
  const dialogText = await evaluate("document.querySelector('[role=dialog]').textContent");
  check("the confirmation shows the file, the old and new value, how it takes effect, and the login warning",
    [`${config}：yes → no`, "生效方式：", "检查不通过时：", "已经打开的会话不受影响"].every((part) => dialogText.includes(part)),
    dialogText.slice(0, 400));
  check("the host is untouched while the confirmation is open", digest(), original);
  await page.shot("baseline-change-confirm.png");
  await evaluate("[...document.querySelectorAll('[role=dialog] button')].find((b) => b.textContent.trim() === '确认修改').click(), true");
  await uiWait("document.querySelector('[data-testid=\"baseline-action-receipt\"]') !== null", "the receipt", 240_000);
  check("sshd itself now refuses root logins", effective("permitrootlogin"), "no");
  // A change is followed by a rescan, which replaces the list (and the receipt
  // with it) while it runs. Read the receipt once the rescan is done: that it
  // is still there then is the point — the operator must not lose it.
  await uiWait(`(${card}) != null && (${card}).querySelector('.baseline-card-verdict')?.classList.contains('is-compliant') === true`, "the rescanned card", 120_000)
    .then(() => check("the page scans again and shows it compliant", true))
    .catch(() => check("the page scans again and shows it compliant", false));
  await uiWait("document.querySelector('[data-testid=\"baseline-action-receipt\"]') !== null", "the receipt after the rescan", 30_000)
    .catch(() => {});
  const receipt = await evaluate("(() => { const element = document.querySelector('[data-testid=\"baseline-action-receipt\"]'); return element === null ? null : { verified: element.dataset.verified, text: element.textContent }; })()");
  check("the receipt is still shown after the rescan", receipt !== null);
  check("the receipt says it was written and read back", receipt?.verified === "true" && receipt.text.includes("已完成并核对"), receipt);
  // The readback is shown as is, so it has to be in the operator's language.
  check("the readback is said in Chinese, without claiming the service is healthy",
    receipt?.text.includes("由独立读回核对") === true && receipt.text.includes("不代表业务已恢复健康"),
    receipt?.text.slice(0, 300) ?? null);
  await page.shot("baseline-changed.png");

  // Restore from history.
  await evaluate("[...document.querySelectorAll('.baseline-tabs button')].find((b) => b.textContent.includes('历史'))?.click(), true");
  await uiWait("document.querySelector('[data-testid=\"baseline-restore-plan\"]') !== null", "the restore button");
  await evaluate("document.querySelector('[data-testid=\"baseline-restore-plan\"]').click(), true");
  await uiWait("document.querySelector('[role=dialog]') !== null", "the restore confirmation");
  check("the restore confirmation says a later change is never overwritten",
    await evaluate("document.querySelector('[role=dialog]').textContent.includes('之后又被改过就不放回')"));
  await evaluate("[...document.querySelectorAll('[role=dialog] button')].find((b) => b.textContent.trim() === '确认放回').click(), true");
  await uiWait("document.querySelector('[data-testid=\"baseline-action-receipt\"]')?.dataset.verified === 'true'", "the restore receipt", 240_000);
  check("the file is byte for byte what it was", digest(), original);
  check("sshd lets root in again, as before", effective("permitrootlogin"), "yes");
  await page.shot("baseline-restored.png");
  check("no console errors", consoleErrors.length === 0, consoleErrors.slice(0, 2));
} catch (error) {
  failures += 1;
  console.log(`FAILED: ${error instanceof Error ? error.message : String(error)}`);
  if (consoleErrors.length > 0) console.log(`console errors: ${consoleErrors.slice(0, 3).join("\n")}`);
  try {
    console.log(`page: ${JSON.stringify(await app?.session?.evaluate("({ nav: document.querySelector('.nav-item.is-active, .nav-item[aria-current]')?.textContent, dialog: document.querySelector('[role=dialog]')?.textContent?.slice(0, 300), notices: [...document.querySelectorAll('[role=alert], [role=status]')].map((n) => n.textContent).slice(0, 5) })"))}`);
  } catch {}
  try { await app?.session?.shot("failure.png"); } catch {}
} finally {
  try { await app?.close(); } catch {}
  if (containerId !== null) {
    try {
      owned();
      docker("rm", "-f", containerId);
      check("the run's own container was removed", !docker("ps", "-a", "--filter", `label=lovelyres-test-run=${runId}`, "--format", "{{.ID}}"));
    } catch (error) {
      failures += 1;
      console.log(`cleanup refused: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
  fs.rmSync(dataRoot, { recursive: true, force: true, maxRetries: 10, retryDelay: 300 });
}
fs.writeFileSync(path.join(evidence, "report.json"), `${JSON.stringify({
  schema: "lovelyhawk-ui-baseline-actions-probe/v1", flavour,
  status: failures === 0 ? "PASS" : "FAIL", generatedAt: new Date().toISOString(), checks,
}, null, 2)}\n`);
console.log(`${failures === 0 ? "PASS" : "FAIL"}: ${checks.filter((item) => item.passed).length}/${checks.length}; evidence in ${evidence}`);
process.exitCode = failures === 0 ? 0 : 1;
