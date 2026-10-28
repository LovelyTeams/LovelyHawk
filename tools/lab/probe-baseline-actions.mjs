// Baseline changes and restores against a real host: a setting is planned,
// approved once, written with a backup, checked by sshd itself, reloaded and
// read back; then put back from history only while the file is still exactly
// as the change left it.
//
// The host is a container this probe creates from the local
// lovelyres-svc:baseline-<deb|el> image (BASELINE=deb by default), whose
// sshd_config is deliberately wrong (PermitRootLogin yes, MaxAuthTries 10, …),
// labelled with this run's id, resource-limited, reachable only on the WSL
// address, and removed at the end after its identity is checked again.
//
//   BASELINE=el node tools/lab/probe-baseline-actions.mjs
import { execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { Sidecar, backendBinary, connect } from "./rpc-harness.mjs";

const flavour = process.env.BASELINE ?? "deb";
if (!["deb", "el"].includes(flavour)) throw new Error(`Unknown BASELINE ${flavour}`);
const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const runId = randomUUID();
const name = `lr-baseline-actions-${flavour}-${runId.slice(0, 8)}`;
const evidence = path.join(repository, "target", "lab-baseline-actions", flavour, runId);
const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "lovelyhawk-baseline-actions-"));
/** Replaced by the file the scan finds PermitRootLogin in (a drop-in on EL9). */
let config = "/etc/ssh/sshd_config";
const checks = [];
let failures = 0;
let containerId = null;
let imageId = null;
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
async function refuses(label, code, run) {
  try {
    await run();
    check(label, false, "it ran");
  } catch (error) {
    check(label, String(error.message).includes(code), String(error.message));
  }
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
const digest = (file = config) => script(`sha256sum ${file} | awk '{print $1}'`);
/** What sshd itself says it will use, independently of the app. */
const effective = (key) => script(`$(command -v sshd || echo /usr/sbin/sshd) -T 2>/dev/null | awk 'tolower($1)==tolower("${key}"){print $2; exit}'`);

const sidecar = new Sidecar(backendBinary(), dataRoot);
try {
  imageId = docker("image", "inspect", `lovelyres-svc:baseline-${flavour}`, "--format", "{{.Id}}");
  const host = wsl("hostname", "-I").split(/\s+/u).find((ip) => /^172\.(1[6-9]|2\d|3[01])\.\d+\.\d+$/u.test(ip));
  if (!host) throw new Error("Missing private WSL address");
  containerId = docker("run", "-d", "--name", name, "--label", `lovelyres-test-run=${runId}`, "--memory", "256m",
    "--cpus", "1", "--pids-limit", "256", "-p", `${host}::22`, imageId);
  const sshPort = Number(owned().NetworkSettings.Ports["22/tcp"][0].HostPort);
  for (let attempt = 0; attempt < 60; attempt += 1) {
    if (script("pgrep -x sshd >/dev/null && echo up || echo down") === "up") break;
    await new Promise((resolve) => setTimeout(resolve, 1_000));
  }
  check("the fixture's sshd lets root in with a password, as planted", effective("permitrootlogin"), "yes");

  const status = await connect(sidecar, { host, port: sshPort, username: "root", password: "LabRoot#2026",
    id: "55555555-5555-4555-8555-555555555501", name: `基线靶机 ${flavour}` });
  if (status?.stage !== "connected") throw new Error(`fixture connect failed: ${JSON.stringify(status)}`);
  const binding = status.bindingHandle;
  const catalog = await sidecar.call("baseline.catalog.get", {});
  const scanFor = () => sidecar.call("baseline.scan", { bindingHandle: binding }, 120_000);
  const byFix = (scan, key) => scan.statuses.find((row) => row.fix.lines.some((line) => line.startsWith(`${key} `)));
  let scan = await scanFor();
  const rootLogin = byFix(scan, "PermitRootLogin");
  const maxTries = byFix(scan, "MaxAuthTries");
  check("the scan finds root login allowed, not compliant", rootLogin?.observed === "yes" && rootLogin.compliant === false, rootLogin);
  // The file sshd actually takes the setting from; the change must land there.
  config = rootLogin.fix.file;
  const original = digest();
  console.log(`  （PermitRootLogin 的生效文件：${config}）`);

  const plan = (action) => sidecar.call("baseline.action.plan", { bindingHandle: binding, action }, 180_000);
  const confirm = (planHandle) => sidecar.call("baseline.action.confirm", { bindingHandle: binding, planHandle }, 60_000);
  const execute = (planHandle) => sidecar.call("baseline.action.execute", { bindingHandle: binding, planHandle }, 300_000);
  const change = (itemHandle, value) => ({ kind: "change", changes: [{ itemHandle, value }], reload: "apply-now" });

  // 1. Plan, refuse unapproved, run once.
  const first = await plan(change(rootLogin.itemHandle, "no"));
  check("the plan says what changes, in which file, and how it takes effect",
    first.action === "change" && first.changes[0]?.before === "yes" && first.changes[0]?.after === "no" &&
    first.changes[0]?.file === config && first.files.includes(config) && (first.reload ?? "").includes("重载") &&
    /[一-鿿]/u.test(first.summary), first);
  check("planning changed nothing on the host", digest(), original);
  await refuses("an unapproved plan does not run", "baseline-action-not-confirmed", () => execute(first.planHandle));
  await confirm(first.planHandle);
  const applied = await execute(first.planHandle);
  check("the change is written, checked and read back", applied.verified === true && applied.restored === false, applied);
  if (applied.verified !== true) console.error(sidecar.stderr.join("").slice(-2000));
  check("sshd itself now refuses root logins", effective("permitrootlogin"), "no");
  check("the session that made the change is still usable (reload, not restart)",
    (await sidecar.call("baseline.scan", { bindingHandle: binding }, 120_000)).statuses.length > 0);
  await refuses("the same plan cannot run twice", "baseline-action-plan-invalid", () => execute(first.planHandle));
  scan = await scanFor();
  check("a new scan reads the setting as compliant", byFix(scan, "PermitRootLogin")?.compliant, true);

  // 2. Refusals that run nothing.
  await refuses("a value the setting does not accept", "baseline-action-invalid-value",
    () => plan(change(rootLogin.itemHandle, "maybe")));
  await refuses("a value it already has", "baseline-action-nothing-to-change",
    () => plan(change(rootLogin.itemHandle, "no")));
  const reportOnly = catalog.items.find((item) => !item.writable);
  await refuses("a setting this tool only reports", "baseline-action-not-writable",
    () => plan(change(reportOnly.itemHandle, reportOnly.recommendation)));
  await refuses("a handle that names no setting", "invalid-params",
    () => plan(change("baseline-item-forged", "no")));
  await refuses("a file path in place of a handle", "invalid-params",
    () => plan(change("/etc/ssh/sshd_config", "no")));

  // 3. Restore from history while the file is as the change left it.
  let history = await sidecar.call("baseline.history.list", { bindingHandle: binding }, 60_000);
  const entry = history.entries[0];
  check("the change is in history, applied and restorable", entry?.state === "applied" && entry?.restorable === true, entry);
  const restore = await plan({ kind: "restore", historyHandle: history.historyHandle, historyItemHandle: entry.historyItemHandle });
  check("the restore plan names the files it puts back", restore.action === "restore" && restore.files.includes(config) &&
    restore.changes.length === 0 && restore.reload === null, restore);
  await confirm(restore.planHandle);
  const restored = await execute(restore.planHandle);
  check("the files are put back and read back", restored.verified === true, restored);
  check("the file is byte for byte what it was", digest(), original);
  history = await sidecar.call("baseline.history.list", { bindingHandle: binding }, 60_000);
  const after = history.entries.find((item) => item.state === "restored");
  check("history says it was restored, and offers no second restore", after?.restorable === false, history.entries);
  await refuses("restoring it again is refused", "baseline-action-not-restorable",
    () => plan({ kind: "restore", historyHandle: history.historyHandle, historyItemHandle: after.historyItemHandle }));

  // 4. A later change by someone else is never overwritten.
  const second = await plan(change(maxTries.itemHandle, "4"));
  await confirm(second.planHandle);
  check("a second change applies", (await execute(second.planHandle)).verified, true);
  const maxFile = maxTries.fix.file;
  script(`printf '%s\\n' '# changed by hand after the tool' >> ${maxFile}`);
  const handEdited = digest(maxFile);
  history = await sidecar.call("baseline.history.list", { bindingHandle: binding }, 60_000);
  const latest = history.entries.find((item) => item.state === "applied");
  const late = await plan({ kind: "restore", historyHandle: history.historyHandle, historyItemHandle: latest.historyItemHandle });
  await confirm(late.planHandle);
  const refused = await execute(late.planHandle);
  check("putting back a file changed since is not done, and says so", refused.verified === false, refused);
  check("the hand edit is still there", digest(maxFile), handEdited);
} catch (error) {
  check("probe completed", false, error instanceof Error ? error.message : String(error));
  const stderr = sidecar.stderr.join("").trim();
  if (stderr !== "") console.error(stderr.slice(-1500));
} finally {
  sidecar.close();
  if (containerId !== null) {
    try {
      owned();
      docker("rm", "-f", containerId);
      check("the fixture container was removed", true);
    } catch (error) {
      check("the fixture container was removed", false, error instanceof Error ? error.message : String(error));
    }
  }
  fs.rmSync(dataRoot, { recursive: true, force: true, maxRetries: 10, retryDelay: 300 });
}

fs.writeFileSync(path.join(evidence, "report.json"), `${JSON.stringify({
  schema: "lovelyhawk-baseline-actions-probe/v1", flavour, runId,
  status: failures === 0 ? "PASS" : "FAIL", generatedAt: new Date().toISOString(), checks,
}, null, 2)}\n`);
console.log(`${failures === 0 ? "PASS" : "FAIL"}: ${checks.length - failures}/${checks.length}; evidence in ${evidence}`);
process.exitCode = failures === 0 ? 0 : 1;
