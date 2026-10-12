// 命令审计, second phase, against a real host: adding command collection to a
// program, taking it off again, and clearing the log — each planned, approved
// once, run, and checked on the host independently of the app.
//
// The host is a container this probe creates from the local lovelyres-lab
// image of one distribution (LAB=ubuntu by default; any of the nine), labelled
// with this run's id, resource-limited, reachable only on the WSL address, and
// removed at the end after its identity is checked again. Only a planted copy
// of a real program (/usr/bin/lhprobe-bin) is ever changed.
//
// Checked: an unapproved plan does not run and an approved one runs once; the
// program is replaced by the collection script with the original kept under
// a backup name, byte for byte; running the command as the ordinary account
// writes a record the page reads back; collecting it again is refused; taking
// collection off puts the original bytes back and removes the backup;
// clearing the log keeps the old log under a backup name; an ordinary account
// without passwordless sudo is refused before anything runs; forged handles
// name nothing.
//
//   LAB=alpine node tools/lab/probe-check-audit-actions.mjs
import { execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { LAB_PORTS } from "./lab-target.mjs";
import { Sidecar, backendBinary, connect } from "./rpc-harness.mjs";

const lab = process.env.LAB ?? "ubuntu";
if (!Object.hasOwn(LAB_PORTS, lab)) throw new Error(`Unknown LAB ${lab}`);
const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const runId = randomUUID();
const name = `lr-audit-actions-${lab}-${runId.slice(0, 8)}`;
const evidence = path.join(repository, "target", "lab-check-audit-actions", lab, runId);
const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "lovelyhawk-audit-actions-"));
const logPath = "/var/log/lovelyres/command-audit.log";
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
/** The container must still be the one this run made, with the limits it was made with. */
function owned() {
  const target = JSON.parse(docker("inspect", containerId))[0];
  if (target.Id !== containerId || target.Image !== imageId || target.Name !== `/${name}` ||
    target.Config.Labels?.["lovelyres-test-run"] !== runId || target.HostConfig.Privileged ||
    target.HostConfig.Memory !== 256 * 1024 * 1024 || target.HostConfig.PidsLimit !== 256) {
    throw new Error("The audit fixture's identity or limits changed");
  }
  return target;
}
/** Runs a script in the fixture as root through stdin, so nothing is re-quoted on the way. */
function script(input, user = "root") {
  owned();
  return execFileSync("wsl.exe", ["-d", "Ubuntu", "-u", "root", "--", "docker", "exec", "-i", "-u", user, containerId, "sh", "-se"],
    { input, encoding: "utf8", windowsHide: true, timeout: 120_000 }).trim();
}
const digest = (file) => script(`sha256sum ${file} | awk '{print $1}'`);

const sidecar = new Sidecar(backendBinary(), dataRoot);
try {
  // 1. The fixture: a planted copy of a real program, and no log yet.
  imageId = docker("image", "inspect", `lovelyres-lab:${lab}`, "--format", "{{.Id}}");
  const host = wsl("hostname", "-I").split(/\s+/u).find((ip) => /^172\.(1[6-9]|2\d|3[01])\.\d+\.\d+$/u.test(ip));
  if (!host) throw new Error("Missing private WSL address");
  containerId = docker("run", "-d", "--name", name, "--label", `lovelyres-test-run=${runId}`, "--memory", "256m",
    "--cpus", "1", "--pids-limit", "256", "-p", `${host}::22`, imageId);
  const sshPort = Number(owned().NetworkSettings.Ports["22/tcp"][0].HostPort);
  // A standalone program on every lab image: ssh-keygen does not care what
  // it is called. (A copy of BusyBox would not run under any name but one of
  // its own commands.)
  script(`cp "$(readlink -f "$(command -v ssh-keygen)")" /usr/bin/lhprobe-bin
[ "$(head -c 4 /usr/bin/lhprobe-bin)" = "$(printf '\\177ELF')" ]
chmod 755 /usr/bin/lhprobe-bin
rm -f /run/nologin /var/run/nologin
rm -rf /var/log/lovelyres`);
  const original = digest("/usr/bin/lhprobe-bin");
  const deploySudo = script("sudo -n true >/dev/null 2>&1 && echo yes || echo no", "deploy");
  check("the fixture has the planted program and no audit log", /^[0-9a-f]{64}$/u.test(original) &&
    script("test ! -e /var/log/lovelyres && echo ok") === "ok", original);

  const open = async (id, username, password) => {
    const status = await connect(sidecar, { host, port: sshPort, username, password, id, name: `审计靶机 ${lab} ${username}` });
    if (status?.stage !== "connected") throw new Error(`fixture connect as ${username} failed: ${JSON.stringify(status)}`);
    return status.bindingHandle;
  };
  const binding = await open("22222222-2222-4222-8222-222222222211", "root", "LabRoot#2026");
  const catalogFor = (bindingHandle) => sidecar.call("check-audit.catalog.get", {
    bindingHandle, input: { customCommandNames: ["lhprobe-bin"] },
  }, 90_000);
  const statusOf = async (bindingHandle, catalog) => {
    const status = await sidecar.call("check-audit.status.collect", {
      bindingHandle, snapshotHandle: catalog.snapshotHandle,
    }, 180_000);
    return status.commands.find((command) => command.name === "lhprobe-bin");
  };
  const plan = (bindingHandle, catalog, action) => sidecar.call("check-audit.action.plan", {
    bindingHandle, snapshotHandle: catalog.snapshotHandle, action,
  }, 120_000);
  const confirm = (bindingHandle, planHandle) => sidecar.call("check-audit.action.confirm", { bindingHandle, planHandle }, 60_000);
  const execute = (bindingHandle, planHandle) => sidecar.call("check-audit.action.execute", { bindingHandle, planHandle }, 300_000);

  let catalog = await catalogFor(binding);
  const handle = catalog.commands.find((command) => command.name === "lhprobe-bin").commandHandle;
  check("the planted program starts without collection", (await statusOf(binding, catalog))?.state, "original");

  // 2. Collect: planned, refused unapproved, run once.
  const collect = await plan(binding, catalog, { kind: "collect", commandHandles: [handle] });
  check("the plan names the command, in words, and says how it is undone",
    collect.action === "collect" && collect.commands.join(",") === "lhprobe-bin" && collect.dangerous === true &&
    /[一-鿿]/u.test(collect.summary) && !/wrapper/iu.test(collect.summary) && (collect.restoreDescription ?? "") !== "", collect);
  check("planning changed nothing on the host", digest("/usr/bin/lhprobe-bin"), original);
  await refuses("an unapproved plan does not run", "check-audit-action-not-confirmed", () => execute(binding, collect.planHandle));
  await confirm(binding, collect.planHandle);
  const collected = await execute(binding, collect.planHandle);
  check("collection is added and read back", collected.verified === true && collected.restored === false, collected);
  const backup = script("ls -a /usr/bin | grep -E '^\\.lhprobe-bin\\.lovelyres-orig-' | head -1");
  check("the original program is kept, byte for byte, under a backup name",
    backup !== "" && digest(`/usr/bin/${backup}`) === original, backup);
  check("the command is now the collection script", script("head -c 2 /usr/bin/lhprobe-bin") === "#!" &&
    script("grep -c LOVELYRES_AUDIT_WRAPPER_V1 /usr/bin/lhprobe-bin") !== "0");
  await refuses("the same plan cannot run twice", "check-audit-action-plan-invalid", () => execute(binding, collect.planHandle));

  // 3. Running the command as the ordinary account is recorded.
  const marker = `lhprobe-${runId.slice(0, 8)}`;
  script(`lhprobe-bin --help >/dev/null 2>&1 || true; lhprobe-bin ${marker} >/dev/null 2>&1 || true`, "deploy");
  check("the host's log now has the ordinary account's call, with its argument",
    script(`grep -c '' ${logPath}`) !== "0", script(`tail -c 400 ${logPath} || true`));
  catalog = await catalogFor(binding);
  check("the page reads the command as collected", (await statusOf(binding, catalog))?.state, "instrumented");
  const log = await sidecar.call("check-audit.log.read", {
    bindingHandle: binding, snapshotHandle: catalog.snapshotHandle, input: { limit: 200, search: null },
  }, 120_000);
  const entry = (log.entries ?? []).find((item) => item.command === "lhprobe-bin" && (item.args ?? "").includes(marker));
  check("the page reads the call back: command, argument and account", entry?.user, "deploy");
  await refuses("collecting it again is refused: it is no longer an original program", "check-audit-action-state-changed",
    () => plan(binding, catalog, { kind: "collect", commandHandles: [catalog.commands.find((c) => c.name === "lhprobe-bin").commandHandle] }));

  // 4. Taking collection off puts the original bytes back.
  const uncollect = await plan(binding, catalog, { kind: "uncollect", commandHandles: [catalog.commands.find((c) => c.name === "lhprobe-bin").commandHandle] });
  await confirm(binding, uncollect.planHandle);
  const uncollected = await execute(binding, uncollect.planHandle);
  check("collection is taken off and read back", uncollected.verified === true, uncollected);
  check("the original program is back, byte for byte", digest("/usr/bin/lhprobe-bin"), original);
  check("the backup is gone", script("ls -a /usr/bin | grep -cE '^\\.lhprobe-bin\\.lovelyres-orig-' || true"), "0");
  catalog = await catalogFor(binding);
  check("the page reads the command as original again", (await statusOf(binding, catalog))?.state, "original");

  // 5. Clearing the log keeps the old one.
  const before = script(`cat ${logPath}`);
  const clear = await plan(binding, catalog, { kind: "clear-log" });
  await confirm(binding, clear.planHandle);
  const cleared = await execute(binding, clear.planHandle);
  check("the log is cleared and read back", cleared.verified === true, cleared);
  check("the new log is empty", script(`wc -c < ${logPath} | tr -d ' '`), "0");
  const kept = script(`ls /var/log/lovelyres | grep -E '^command-audit\\.log\\.clear-' | head -1`);
  check("the old log is kept under a backup name, unchanged", kept !== "" && script(`cat /var/log/lovelyres/${kept}`) === before, kept);

  // 6. A command that is one name of a multi-call program (BusyBox) is never
  //    collected: that would replace every command on the host, sh included.
  const statuses = await sidecar.call("check-audit.status.collect", {
    bindingHandle: binding, snapshotHandle: catalog.snapshotHandle,
  }, 180_000);
  const multi = statuses.commands.find((item) => item.state === "multi-call");
  const usesBusybox = script("[ \"$(readlink -f /bin/ls)\" = /bin/busybox ] && echo yes || echo no") === "yes";
  check("commands that are BusyBox are reported as such, and only there", (multi !== undefined) === usesBusybox, { multi: multi?.name ?? null, usesBusybox });
  if (multi !== undefined) {
    const busybox = digest("/bin/busybox");
    await refuses(`collecting ${multi.name} (BusyBox) is refused`, "check-audit-action-state-changed",
      () => plan(binding, catalog, { kind: "collect", commandHandles: [multi.commandHandle] }));
    check("BusyBox is untouched", digest("/bin/busybox"), busybox);
  }

  // 7. Forged handles name nothing.
  await refuses("a handle from no catalog names no command", "check-audit-action-command-unavailable",
    () => plan(binding, catalog, { kind: "collect", commandHandles: ["00000000-0000-4000-8000-00000000dead"] }));
  await refuses("a path in place of a handle is refused", "invalid-params",
    () => plan(binding, catalog, { kind: "collect", commandHandles: ["/usr/bin/lhprobe-bin"] }));

  // 8. The ordinary account: refused before anything runs unless it may sudo.
  const deployBinding = await open("22222222-2222-4222-8222-222222222212", "deploy", "LabDeploy#2026");
  const deployCatalog = await catalogFor(deployBinding);
  const deployHandle = deployCatalog.commands.find((command) => command.name === "lhprobe-bin").commandHandle;
  if (deploySudo === "no") {
    await refuses("an account without passwordless sudo is told so, before anything runs", "check-audit-action-needs-privilege",
      () => plan(deployBinding, deployCatalog, { kind: "collect", commandHandles: [deployHandle] }));
    check("nothing changed on the host", digest("/usr/bin/lhprobe-bin"), original);
  } else {
    const sudoPlan = await plan(deployBinding, deployCatalog, { kind: "collect", commandHandles: [deployHandle] });
    check("an account with passwordless sudo can plan", sudoPlan.action, "collect");
    await sidecar.call("check-audit.action.cancel", { bindingHandle: deployBinding, planHandle: sudoPlan.planHandle }, 30_000);
  }
} catch (error) {
  check("probe completed", false, error instanceof Error ? error.message : String(error));
  const stderr = sidecar.stderr.join("").trim();
  if (stderr !== "") console.error(stderr.slice(-1200));
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
  fs.rmSync(dataRoot, { recursive: true, force: true });
}

fs.writeFileSync(path.join(evidence, "report.json"), `${JSON.stringify({
  schema: "lovelyhawk-check-audit-actions-probe/v1", lab, runId,
  status: failures === 0 ? "PASS" : "FAIL", generatedAt: new Date().toISOString(), checks,
}, null, 2)}\n`);
console.log(`${failures === 0 ? "PASS" : "FAIL"}: ${checks.length - failures}/${checks.length}; evidence in ${evidence}`);
process.exitCode = failures === 0 ? 0 : 1;
