// Real sshd oracle and baseline RPC, using only a newly created owned container.
// Does not reload sshd or change the running daemon's configuration.
import { execFileSync, spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Sidecar, backendBinary, connect } from "./rpc-harness.mjs";

const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const runId = randomUUID(), name = `lh-sshd-includes-${runId.slice(0, 8)}`;
const evidence = path.resolve(process.env.LOVELYHAWK_PROBE_EVIDENCE ?? path.join(repository, "target/lab-sshd-includes"), runId);
fs.mkdirSync(evidence, { recursive: true });
const report = { runId, at: new Date().toISOString(), scope: "Owned Debian container; configuration parsing and read-only planning, no reload or host/VM acceptance.", checks: [] };
const keepalive = spawn("wsl.exe", ["-d", "Ubuntu", "-u", "root", "--", "cat"], { windowsHide: true, stdio: ["pipe", "ignore", "ignore"] });
const wsl = (...args) => execFileSync("wsl.exe", ["-d", "Ubuntu", "-u", "root", "--", ...args],
  { encoding: "utf8", windowsHide: true, timeout: 120_000, maxBuffer: 2 * 1024 * 1024 }).trim();
const docker = (...args) => wsl("docker", ...args);
let containerId, imageId, sidecar;
function owned() {
  const target = JSON.parse(docker("inspect", containerId))[0];
  if (target.Id !== containerId || target.Image !== imageId || target.Name !== `/${name}` ||
    target.Config.Labels?.["lovelyhawk-test-run"] !== runId || target.HostConfig.Privileged ||
    target.HostConfig.NetworkMode !== "bridge" || target.Mounts.length !== 0 ||
    target.HostConfig.Memory !== 256 * 1024 * 1024 || target.HostConfig.PidsLimit !== 256 || target.HostConfig.NanoCpus !== 1_000_000_000) {
    throw new Error("Unverified fixture identity, network, mounts or limits");
  }
  return target;
}
function script(input) {
  owned();
  return execFileSync("wsl.exe", ["-d", "Ubuntu", "-u", "root", "--", "docker", "exec", "-i", containerId, "sh", "-se"],
    { input, encoding: "utf8", windowsHide: true, timeout: 120_000, maxBuffer: 2 * 1024 * 1024 }).trim();
}
function write(file, body) {
  owned();
  execFileSync("wsl.exe", ["-d", "Ubuntu", "-u", "root", "--", "docker", "exec", "-i", containerId,
    "tee", file], { input: body, windowsHide: true, timeout: 30_000, stdio: ["pipe", "ignore", "pipe"] });
}
function check(label, passed, detail) {
  report.checks.push({ label, passed: Boolean(passed), detail });
  console.log(`${passed ? "PASS" : "FAIL"} ${label}`);
}
const main = "/etc/ssh/sshd_config", drop = "/etc/ssh/sshd_config.d/";
const match = "Match Address 203.0.113.0/24\n";
const fixtures = [
  { name: "global include precedes main", main: "Include sshd_config.d/00.conf\nPermitRootLogin no\n", files: { "00.conf": "PermitRootLogin yes\n" }, observed: "yes", source: "00.conf", oracle: ["yes", "yes"] },
  { name: "global main precedes include", main: "PermitRootLogin no\nInclude sshd_config.d/00.conf\n", files: { "00.conf": "PermitRootLogin yes\n" }, observed: "no", source: main, oracle: ["no", "no"] },
  { name: "conditional include overrides global", main: `PermitRootLogin no\n${match}Include sshd_config.d/00.conf\n`, files: { "00.conf": "PermitRootLogin yes\n" }, observed: "conditional", source: "00.conf", oracle: ["no", "yes"] },
  { name: "conditional nested include", main: `PermitRootLogin no\n${match}Include sshd_config.d/00.conf\n`, files: { "00.conf": "Include sshd_config.d/10.conf\n", "10.conf": "PermitRootLogin yes\n" }, observed: "conditional", source: "10.conf", oracle: ["no", "yes"] },
  { name: "conditional parent resumes after empty include", main: `PermitRootLogin no\n${match}Include sshd_config.d/00.conf\nPermitRootLogin yes\n`, files: { "00.conf": "# empty\n" }, observed: "conditional", source: main, oracle: ["no", "yes"] },
  { name: "conditional parent resumes after unmatched include", main: `PermitRootLogin no\n${match}Include sshd_config.d/missing*.conf\nPermitRootLogin yes\n`, files: {}, observed: "conditional", source: main, oracle: ["no", "yes"] },
  { name: "child Match does not leak into global parent", main: "Include sshd_config.d/00.conf\nPermitRootLogin yes\n", files: { "00.conf": `${match}Include sshd_config.d/empty.inc\n`, "empty.inc": "# empty\n" }, observed: "yes", source: main, oracle: ["yes", "yes"] },
  { name: "child Match does not leak into glob sibling", main: "Include sshd_config.d/*.conf\n", files: { "00.conf": `${match}Include sshd_config.d/empty.inc\n`, "10.conf": "PermitRootLogin yes\n", "empty.inc": "# empty\n" }, observed: "yes", source: "10.conf", oracle: ["yes", "yes"] },
  { name: "child Match does not leak into nested parent", main: "Include sshd_config.d/00.conf\n", files: { "00.conf": "Include sshd_config.d/10.conf\nPermitRootLogin yes\n", "10.conf": `${match}Include sshd_config.d/empty.inc\n`, "empty.inc": "# empty\n" }, observed: "yes", source: "00.conf", oracle: ["yes", "yes"] },
  { name: "conditional finding survives later global setting", main: "Include sshd_config.d/00.conf\nPermitRootLogin no\n", files: { "00.conf": `${match}Include sshd_config.d/10.conf\n`, "10.conf": "PermitRootLogin yes\n" }, observed: "conditional", source: "10.conf", oracle: ["no", "yes"] },
  { name: "same file included globally and conditionally", main: `Include sshd_config.d/00.conf\n${match}Include sshd_config.d/00.conf\n`, files: { "00.conf": "PermitRootLogin yes\n" }, observed: "conditional", source: "00.conf", oracle: ["yes", "yes"] },
  { name: "irrelevant conditional key does not replace root source", main: `PermitRootLogin yes\n${match}Include sshd_config.d/00.conf\n`, files: { "00.conf": "X11Forwarding no\n" }, observed: "yes", source: main, oracle: ["yes", "yes"] },
  { name: "quoted include stays unverified", main: `PermitRootLogin no\n${match}Include "sshd_config.d/00.conf"\n`, files: { "00.conf": "PermitRootLogin yes\n" }, observed: "unverified", source: main, oracle: ["no", "yes"] },
  { name: "conditional source outside managed files stays unverified", main: `PermitRootLogin no\n${match}Include /tmp/lh-sshd-external.conf\n`, files: { "/tmp/lh-sshd-external.conf": "PermitRootLogin yes\n" }, observed: "unverified", source: main, oracle: ["no", "yes"] },
  { name: "conditional symlink stays unsupported", main: `PermitRootLogin no\n${match}Include sshd_config.d/00.conf\n`, files: { "/tmp/lh-sshd-external.conf": "PermitRootLogin yes\n" }, setup: "ln -s /tmp/lh-sshd-external.conf /etc/ssh/sshd_config.d/00.conf", observed: "unsupported", source: main, oracle: ["no", "yes"] },
];
try {
  imageId = docker("image", "inspect", "lovelyres-svc:baseline-deb", "--format", "{{.Id}}");
  const host = wsl("hostname", "-I").split(/\s+/u).find(ip => /^172\.(1[6-9]|2\d|3[01])\.\d+\.\d+$/u.test(ip));
  if (!host) throw new Error("No private WSL address");
  containerId = docker("run", "-d", "--name", name, "--label", `lovelyhawk-test-run=${runId}`, "--memory", "256m", "--cpus", "1", "--pids-limit", "256", "-p", `${host}::22`, imageId);
  const target = owned();
  report.target = { id: target.Id, image: target.Image, name: target.Name, mounts: target.Mounts, network: target.HostConfig.NetworkMode };
  report.environment = script("cat /etc/os-release; uname -m; /usr/sbin/sshd -V 2>&1; awk -W version 2>&1");
  sidecar = new Sidecar(backendBinary(), path.join(evidence, "data"));
  const connected = await connect(sidecar, { host, port: Number(target.NetworkSettings.Ports["22/tcp"][0].HostPort), username: "root", password: "LabRoot#2026", id: runId, name });
  if (connected?.stage !== "connected") throw new Error("Fixture SSH connection failed");
  check("owned SSH target connected", true);
  const bindingHandle = connected.bindingHandle;
  for (const fixture of fixtures) {
    // Fixed namespace inside the verified disposable container, never a host path.
    script("test ! -L /etc/ssh/sshd_config.d; test -d /etc/ssh/sshd_config.d; find /etc/ssh/sshd_config.d -mindepth 1 -maxdepth 1 -type f -delete; find /etc/ssh/sshd_config.d -mindepth 1 -maxdepth 1 -type l -delete");
    write(main, fixture.main);
    for (const [file, body] of Object.entries(fixture.files)) write(file.startsWith("/") ? file : drop + file, body);
    if (fixture.setup) script(fixture.setup);
    const oracle = ["198.51.100.1", "203.0.113.1"].map(address => script(`/usr/sbin/sshd -T -C user=root,host=localhost,addr=${address} | awk '$1=="permitrootlogin"{print $2}'`));
    check(`${fixture.name}: sshd connection oracle`, JSON.stringify(oracle) === JSON.stringify(fixture.oracle), oracle);
    const scan = await sidecar.call("baseline.scan", { bindingHandle });
    const row = scan.statuses.find(item => item.fix.lines.some(line => line.startsWith("PermitRootLogin ")));
    const observed = ["yes", "no"].includes(fixture.observed) ? row?.observed : row?.observedKind;
    const source = fixture.source.startsWith("/") ? fixture.source : drop + fixture.source;
    check(`${fixture.name}: observation and source`, observed === fixture.observed && row.fix.file === source, row);
    if (["conditional", "unverified", "unsupported"].includes(fixture.observed)) {
      check(`${fixture.name}: never compliant`, row?.compliant === false, row?.compliant);
      let refused = false, refusal;
      try {
        const plan = await sidecar.call("baseline.action.plan", { bindingHandle, action: { kind: "change", changes: [{ itemHandle: row.itemHandle, value: "no" }], reload: "defer" } });
        await sidecar.call("baseline.action.cancel", { bindingHandle, planHandle: plan.planHandle });
      } catch (error) { refusal = error.message; refused = refusal.startsWith("baseline-action-not-writable:"); }
      check(`${fixture.name}: automatic change refused`, refused, refusal);
    }
  }
} catch (error) {
  check("probe completed", false, error instanceof Error ? error.message : String(error));
} finally {
  sidecar?.close();
  if (containerId) {
    try { owned(); docker("rm", "-f", containerId); check("owned fixture removed", true); }
    catch (error) { check("owned fixture removed", false, String(error)); }
  }
  keepalive.kill();
  report.status = report.checks.every(check => check.passed) ? "PASS" : "FAIL";
  fs.writeFileSync(path.join(evidence, "report.json"), JSON.stringify(report, null, 2));
  if (sidecar) fs.writeFileSync(path.join(evidence, "backend.log"), sidecar.stderr.join(""));
  console.log(`${report.status}: ${report.checks.filter(check => check.passed).length}/${report.checks.length}; ${evidence}`);
  process.exitCode = report.status === "PASS" ? 0 : 1;
}
