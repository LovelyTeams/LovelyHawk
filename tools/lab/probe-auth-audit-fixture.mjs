// Production shell commands in a private chroot with a modeled auditctl.
// This verifies deltas and refusal/recovery behavior, NOT kernel audit support.
import { spawn, spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const runId = randomUUID();
const root = `/tmp/lovelyhawk-audit-fixture-${runId}`;
const evidence = path.join(repository, "target/lab-auth-audit-fixture", runId);
fs.mkdirSync(evidence, { recursive: true });
const report = { runId, at: new Date().toISOString(), scope: "Modeled auditctl in an owned private chroot; no real kernel audit operations", checks: [] };
const keepalive = spawn("wsl.exe", ["-d", "Ubuntu", "-u", "root", "--", "cat"], { windowsHide: true, stdio: ["pipe", "ignore", "ignore"] });
const sq = value => `'${value.replaceAll("'", "'\\''")}'`;
const run = (args, input = "") => spawnSync("wsl.exe", ["-d", "Ubuntu", "-u", "root", "--", ...args],
  { input, encoding: "utf8", windowsHide: true, timeout: 120_000, maxBuffer: 4 * 1024 * 1024 });
const shell = input => {
  const result = run(["bash", "-se"], input);
  if (result.status !== 0) throw new Error(result.stderr || result.stdout || String(result.error));
  return result.stdout.trim();
};
const chroot = input => run(["chroot", root, "/bin/sh", "-se"], input);
function inside(input) {
  const result = chroot(input);
  if (result.status !== 0) throw new Error(result.stderr || result.stdout || String(result.error));
  return result.stdout.trim();
}
function check(label, passed, detail) {
  report.checks.push({ label, passed: Boolean(passed), detail });
  console.log(`${passed ? "PASS" : "FAIL"} ${label}`);
  if (!passed) throw new Error(label);
}
const source = fs.readFileSync(path.join(repository, "crates/lovelyhawk-core/src/baseline_host.rs"), "utf8");
const probe = source.match(/const PROBE: &str = r#"([\s\S]*?)"#;/u)?.[1];
if (!probe) throw new Error("No production host probe");
const observed = () => inside(`${probe}\nlh_audit`);
function exportCommands(observation, current, remoteRoot) {
  const input = path.join(evidence, "host-input.json");
  fs.writeFileSync(input, JSON.stringify({ observation, current, remoteRoot }));
  const result = spawnSync("cargo", ["test", "--locked", "-p", "lovelyhawk-core", "export_owned_fixture_commands", "--", "--ignored", "--exact", "baseline::host::tests::export_owned_fixture_commands"],
    { cwd: repository, env: { ...process.env, LOVELYHAWK_HOST_BASELINE_FIXTURE: input }, encoding: "utf8", windowsHide: true, timeout: 300_000, maxBuffer: 4 * 1024 * 1024 });
  fs.appendFileSync(path.join(evidence, "export.log"), result.stdout + result.stderr);
  if (result.status !== 0) throw new Error("Production fixture exporter failed; see export.log");
  return JSON.parse(fs.readFileSync(path.join(evidence, "host-commands.json"), "utf8"));
}
const rulesFile = "/etc/audit/rules.d/70-lovelyhawk-auth.rules";
const other = "-w /var/log/example -p wa -k operator_log";
const wanted = ["/etc/passwd", "/etc/group", "/etc/shadow", "/etc/gshadow"].map(file => `-w ${file} -p wa -k lovelyhawk_auth`);
const rules = () => inside("cat /rules-state").split("\n").filter(Boolean).sort();
const reset = () => inside(`rm -f ${rulesFile} /fail-watch /locked /fail-list; printf '%s\n' ${sq(other)} > /rules-state`);
try {
  shell(`test ! -e ${sq(root)}\nmkdir -m 700 ${sq(root)}\nprintf '%s' ${sq(runId)} > ${sq(root + "/.owner")}\n` +
    `for tool in sh dash stat sha256sum awk head wc sort tr base64 cat install cp mkdir chmod chown rm grep readlink mv id uname touch; do
      bin=$(command -v "$tool"); cp -L --parents "$bin" ${sq(root)}
      ldd "$bin" | awk '{ for(i=1;i<=NF;i++) if($i ~ /^\\//) print $i }' | while IFS= read -r lib; do cp -L --parents "$lib" ${sq(root)}; done
    done
    mkdir -p ${sq(root)}/{bin,usr/sbin,usr/bin,etc/audit/rules.d,var/lib,proc/sys/kernel/random,dev}
    cp -L /bin/sh ${sq(root + "/bin/sh")}
    touch ${sq(root + "/dev/null")}
    chmod 666 ${sq(root + "/dev/null")}
    printf '11111111-2222-4333-8444-555555555555\\n' > ${sq(root + "/proc/sys/kernel/random/boot_id")}
    for file in passwd group shadow gshadow; do printf 'fixture-only\\n' > ${sq(root)}/etc/$file; done
    chmod 600 ${sq(root)}/etc/{shadow,gshadow}
    cat > ${sq(root + "/usr/bin/uname")} <<'LH_UNAME'
#!/bin/sh
printf '6.8.0-fixture\\n'
LH_UNAME
    cat > ${sq(root + "/usr/bin/systemd-detect-virt")} <<'LH_VIRT'
#!/bin/sh
printf 'none\\n'
exit 1
LH_VIRT
    cat > ${sq(root + "/usr/sbin/auditctl")} <<'LH_AUDIT'
#!/bin/sh
set -eu
case "$1" in
  -s) if [ -e /locked ]; then printf 'enabled 2\\npid 123\\n'; else printf 'enabled 1\\npid 123\\n'; fi;;
  -l) [ ! -e /fail-list ] || exit 1; cat /rules-state;;
  -w|-W)
    [ "$#" = 6 ] && [ "$3" = -p ] && [ "$4" = wa ] && [ "$5" = -k ] && [ "$6" = lovelyhawk_auth ] || exit 70
    case "$2" in /etc/passwd|/etc/group|/etc/shadow|/etc/gshadow) ;; *) exit 71;; esac
    [ ! -e /fail-watch ] || [ "$(cat /fail-watch)" != "$2" ] || exit 72
    rule="-w $2 -p wa -k lovelyhawk_auth"
    if [ "$1" = -w ]; then
      ! grep -F -x -- "$rule" /rules-state >/dev/null || exit 73
      printf '%s\\n' "$rule" >> /rules-state
    else
      grep -F -x -- "$rule" /rules-state >/dev/null || exit 74
      awk -v target="$rule" '$0 != target' /rules-state > /rules-next; mv /rules-next /rules-state
    fi;;
  *) exit 75;;
esac
LH_AUDIT
    chmod 755 ${sq(root)}/usr/bin/{uname,systemd-detect-virt} ${sq(root)}/usr/sbin/auditctl
  `);
  reset();
  let initial = observed();
  let commands = exportCommands(initial);
  let result = chroot(commands.apply);
  check("production apply adds only four fixed watches", result.status === 0 && JSON.stringify(rules()) === JSON.stringify([other, ...wanted].sort()), { exit: result.status, stderr: result.stderr });
  check("persisted fragment has exact root-owned restricted attributes", inside(`stat -c '%a:%u:%g' ${rulesFile}`) === "600:0:0");
  check("re-executing a stale plan does not duplicate rules", chroot(commands.apply).status !== 0 && rules().length === 5);
  const same = exportCommands(observed());
  check("already present watches generate no add or remove command", !same.apply.includes("auditctl -w") && !same.restore.includes("auditctl -W"));
  result = chroot(commands.restore);
  check("restore removes only this plan's watches and fragment", result.status === 0 && JSON.stringify(rules()) === JSON.stringify([other]) && inside(`test ! -e ${rulesFile}; printf ok`) === "ok", { exit: result.status, stderr: result.stderr });

  reset(); initial = observed(); commands = exportCommands(initial); inside(commands.apply);
  inside(`printf '%s\n' '-w /opt/business -p wa -k business' >> /rules-state`);
  const changed = rules();
  check("later unrelated runtime change blocks restore before deletion", chroot(commands.restore).status !== 0 && JSON.stringify(rules()) === JSON.stringify(changed));
  reset(); initial = observed(); commands = exportCommands(initial); inside(commands.apply);
  inside(`printf '# later edit\n' >> ${rulesFile}`);
  check("later fragment edit blocks restore before watch deletion", chroot(commands.restore).status !== 0 && rules().length === 5);
  reset(); initial = observed(); commands = exportCommands(initial);
  inside("mv /etc/shadow /etc/shadow.old; printf 'new fixture\n' > /etc/shadow; chmod 600 /etc/shadow");
  check("replaced watched file invalidates the plan", chroot(commands.apply).status !== 0 && rules().length === 1);

  reset(); initial = observed(); commands = exportCommands(initial);
  inside("printf '/etc/group' > /fail-watch");
  result = chroot(commands.apply);
  check("partial insertion failure is reported as failure", result.status !== 0 && rules().length === 2);
  const partial = observed();
  commands = exportCommands(initial, partial, commands.root);
  check("partial recovery is generated from the original plan", typeof commands.recovery?.Ok === "string");
  inside("rm /fail-watch");
  result = chroot(commands.recovery.Ok);
  check("partial recovery removes only inserted rules and its fragment", result.status === 0 && rules().length === 1 && inside(`test ! -e ${rulesFile}; printf ok`) === "ok");
  reset(); initial = observed(); commands = exportCommands(initial);
  inside("printf '/etc/group' > /fail-watch"); chroot(commands.apply);
  inside(`printf '%s\n' '-w /opt/business -p wa -k business' >> /rules-state`);
  commands = exportCommands(initial, observed(), commands.root);
  check("partial recovery refuses concurrent unrelated changes", typeof commands.recovery?.Err === "string");
  reset(); inside("touch /locked");
  check("immutable audit mode remains unavailable", chroot(`${probe}\nlh_audit`).status !== 0);
  inside("rm /locked; touch /fail-list");
  check("failed audit read is not an empty successful ruleset", chroot(`${probe}\nlh_audit`).status !== 0);
  inside("rm /fail-list; mv /usr/bin/systemd-detect-virt /usr/bin/fixture-virt-disabled");
  check("unknown host-versus-container environment refuses audit access", chroot(`${probe}\nlh_audit`).status !== 0);
} catch (error) {
  report.failure = String(error.stack ?? error); process.exitCode = 1; console.error(report.failure);
} finally {
  try { shell(`test ${sq(root)} = /tmp/lovelyhawk-audit-fixture-${runId}\ntest "$(cat ${sq(root + "/.owner")})" = ${sq(runId)}\ntest "$(readlink -f ${sq(root)})" = ${sq(root)}\nrm -rf -- ${sq(root)}`); }
  catch (error) { report.cleanupFailure = String(error); process.exitCode = 1; }
  keepalive.stdin.end();
  fs.writeFileSync(path.join(evidence, "report.json"), `${JSON.stringify(report, null, 2)}\n`);
  console.log(`Evidence: ${evidence}`);
}
