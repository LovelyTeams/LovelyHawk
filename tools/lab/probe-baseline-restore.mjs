// Actual core plans, SSH writes and independent restore verification. Owned lab only.
import { execFileSync, spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Sidecar, connect } from "./rpc-harness.mjs";

const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const runId = randomUUID(), name = `lr-baseline-restore-${runId.slice(0, 8)}`;
const evidence = path.join(repository, "target/lab-baseline-restore", runId);
const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "lovelyres-baseline-restore-"));
fs.mkdirSync(evidence, { recursive: true });
const checks = [];
let containerId, imageId, version, platform, sidecar, failure;
const keepalive = spawn("wsl.exe", ["-d", "Ubuntu", "-u", "root", "--", "cat"], { windowsHide: true, stdio: ["pipe", "ignore", "ignore"] });
keepalive.once("error", error => { failure ??= String(error); });
const wsl = (...args) => execFileSync("wsl.exe", ["-d", "Ubuntu", "-u", "root", "--", ...args], { encoding: "utf8", windowsHide: true, timeout: 60_000, maxBuffer: 2 * 1024 * 1024 }).trim();
const docker = (...args) => wsl("docker", ...args);
function check(label, actual) { checks.push({ label, passed: Boolean(actual) }); console.log(`${actual ? "PASS" : "FAIL"} ${label}`); if (!actual) throw new Error(label); }
function owned() {
  const target = JSON.parse(docker("inspect", containerId))[0];
  if (target.Id !== containerId || target.Image !== imageId || target.Name !== `/${name}` || target.Config.Labels?.["lovelyres-test-run"] !== runId ||
    target.HostConfig.Privileged || target.HostConfig.NetworkMode !== "bridge" || target.Mounts.some(mount => mount.Type !== "tmpfs" || mount.Destination !== "/data") ||
    target.HostConfig.Tmpfs?.["/data"] !== "rw,noexec,nosuid,size=64m") throw new Error("Fixture identity or storage changed");
  return target;
}
const onHost = (...args) => { owned(); return docker("exec", containerId, ...args); };
async function coreSuite() {
  await new Promise((resolve, reject) => {
    let transcript = "";
    const child = spawn("cargo", ["test", "--locked", "--package", "lovelyhawk-core", "baseline::restore_lab::owned_baseline_restore", "--lib", "--", "--ignored", "--exact", "--nocapture"],
      { cwd: repository, env: { ...process.env, LOVELYHAWK_BASELINE_RESTORE_ROOT: dataRoot, LOVELYHAWK_BASELINE_RESTORE_RUN: runId }, windowsHide: true });
    const log = fs.createWriteStream(path.join(evidence, "core-restore.log"));
    child.stdout.on("data", chunk => { transcript += chunk.toString(); log.write(chunk); process.stdout.write(chunk); });
    child.stderr.on("data", chunk => { log.write(chunk); process.stdout.write(chunk); });
    child.once("error", reject);
    child.once("close", code => {
      log.end();
      for (const line of transcript.split(/\r?\n/u)) if (line.startsWith("BASELINE_RESTORE_CHECK ")) checks.push({ label: line.slice("BASELINE_RESTORE_CHECK ".length), passed: true });
      if (code === 0 && transcript.includes("BASELINE_RESTORE_SUITE_COMPLETE") && transcript.includes("1 passed; 0 failed")) resolve();
      else reject(new Error(`Owned core restore suite failed (exit ${code})`));
    });
  });
}
try {
  imageId = docker("image", "inspect", "lovelyres-svc:redis", "--format", "{{.Id}}");
  const host = wsl("hostname", "-I").split(/\s+/u).find(ip => /^172\.(1[6-9]|2\d|3[01])\./u.test(ip));
  if (!host) throw new Error("Missing private WSL address");
  containerId = docker("run", "-d", "--name", name, "--label", `lovelyres-test-run=${runId}`, "--memory", "256m", "--cpus", "1", "--pids-limit", "128", "--tmpfs", "/data:rw,noexec,nosuid,size=64m", "-p", `${host}::22`, imageId);
  check("owned fixture has bounded resources and no host mounts or privileged access", Boolean(owned()));
  version = onHost("redis-server", "--version");
  platform = onHost("sh", "-c", "cat /etc/os-release; uname -m");
  onHost("sh", "-c", `printf '%s' '${runId}' > /tmp/lovelyres-baseline-restore-run`);
  onHost("redis-server", "/etc/redis/redis.conf", "--daemonize", "yes");
  sidecar = new Sidecar(path.join(repository, "target/debug/lovelyhawk-backend.exe"), dataRoot);
  await connect(sidecar, { host, port: Number(owned().NetworkSettings.Ports["22/tcp"][0].HostPort), username: "root", password: "LabRoot#2026", id: runId, name });
  sidecar.close(); sidecar = undefined;
  owned(); await coreSuite();
  check("actual core plan confirmation execution and restore suite completed", true);
} catch (error) { failure = String(error); console.error(failure); process.exitCode = 1; }
finally {
  sidecar?.close();
  if (containerId) { try { owned(); docker("rm", "-f", containerId); check("owned container removed", true); } catch (error) { failure ??= String(error); process.exitCode = 1; } }
  try {
    const resolved = fs.realpathSync(dataRoot), temp = fs.realpathSync(os.tmpdir());
    if (path.dirname(resolved) !== temp || !/^lovelyres-baseline-restore-[A-Za-z0-9]{6}$/u.test(path.basename(resolved))) throw new Error("Unexpected fixture data root");
    fs.rmSync(resolved, { recursive: true }); check("isolated application data removed", true);
  } catch (error) { failure ??= String(error); process.exitCode = 1; }
  fs.writeFileSync(path.join(evidence, "report.json"), JSON.stringify({ runId, date: new Date().toISOString(), imageId, version, platform, checks, error: failure ?? null,
    limits: ["core integration; baseline mutation and restore are not connected to the desktop app", "Redis history samples use explicit fixture before and after evidence, not a production Redis generic writer", "complete file readback does not establish runtime or business health", "shell prechecks do not provide atomic multi-file or adversarial filesystem transaction guarantees"] }, null, 2));
  console.log(`Evidence: ${evidence}`); keepalive.stdin.end();
}
