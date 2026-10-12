// Owned, disposable Nginx process-runtime and core repair integration.
// Installs Python ONLY inside this new fixture; product discovery never installs it.
import { execFileSync, spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Sidecar, connect } from "./rpc-harness.mjs";

const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const runId = randomUUID(), name = `lr-nginx-process-${runId.slice(0, 8)}`;
const evidenceRoot = path.join(repository, "target/lab-nginx-process", runId);
const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "lovelyres-nginx-process-"));
fs.mkdirSync(evidenceRoot, { recursive: true });
const checks = [];
let containerId, imageId, sidecar, version, error;
// A live WSL client prevents idle shutdown during the native Rust build. EOF
// releases this task's cat process; no host service or global WSL setting changes.
const keepalive = spawn("wsl.exe", ["-d", "Ubuntu", "-u", "root", "--", "cat"],
  { windowsHide: true, stdio: ["pipe", "ignore", "ignore"] });
keepalive.once("error", (failure) => { error ??= String(failure); });
function check(label, actual) {
  checks.push({ label, passed: Boolean(actual) });
  console.log(`${actual ? "PASS" : "FAIL"} ${label}`);
  if (!actual) throw new Error(label);
}
function wsl(...args) {
  return execFileSync("wsl.exe", ["-d", "Ubuntu", "-u", "root", "--", ...args],
    { encoding: "utf8", windowsHide: true, timeout: 120_000, maxBuffer: 2 * 1024 * 1024 }).trim();
}
const docker = (...args) => wsl("docker", ...args);
function owned() {
  const found = JSON.parse(docker("inspect", containerId))[0];
  if (found.Id !== containerId || found.Image !== imageId || found.Name !== `/${name}` ||
    found.Config.Labels?.["lovelyres-test-run"] !== runId || found.HostConfig.Privileged ||
    found.Mounts.length !== 0 || found.HostConfig.NetworkMode !== "bridge") throw new Error("Fixture identity changed");
  return found;
}
const onHost = (...args) => { owned(); return docker("exec", containerId, ...args); };
const helper = fs.readFileSync(path.join(repository, "crates/lovelyhawk-core/src/nginx_process.py"), "utf8");
function invoke(request) {
  try { return JSON.parse(onHost("python3", "-I", "-c", helper, JSON.stringify(request))); }
  catch (failure) {
    if (failure.stdout) return JSON.parse(String(failure.stdout));
    throw failure;
  }
}
function fixture(file, content) {
  if (!["/etc/nginx/nginx.conf", "/etc/nginx/conf.d/lovelyres-process.conf", "/tmp/lovelyres-nginx-run"].includes(file))
    throw new Error("Unknown fixture path");
  onHost("sh", "-c", `printf '%s' '${Buffer.from(content).toString("base64")}' | base64 -d > '${file}'`);
}
const site = `server {
  listen 127.0.0.1:8080;
  root /tmp/lr-nginx-www;
  server_tokens on;
  autoindex on;
  access_log /tmp/lr-nginx-access.log;
}
`;
function runCargo(env) {
  return new Promise((resolve, reject) => {
    let transcript = "";
    const child = spawn("cargo", ["test", "--locked", "--package", "lovelyhawk-core", "middleware::nginx_lab::owned_nginx_process_repair", "--lib", "--", "--ignored", "--exact", "--nocapture"],
      { cwd: repository, env: { ...process.env, ...env }, windowsHide: true });
    const output = fs.createWriteStream(path.join(evidenceRoot, "core-repair.log"));
    child.stdout.on("data", (chunk) => { transcript += chunk.toString(); process.stdout.write(chunk); output.write(chunk); });
    child.stderr.on("data", (chunk) => { process.stdout.write(chunk); output.write(chunk); });
    child.once("error", reject);
    child.once("exit", (code) => {
      output.end();
      if (code === 0 && transcript.includes("NGINX_CORE_SUITE_COMPLETE") && transcript.includes("1 passed; 0 failed")) {
        for (const line of transcript.split(/\r?\n/u)) if (line.startsWith("NGINX_CORE_CHECK "))
          check(line.slice("NGINX_CORE_CHECK ".length), true);
        resolve();
      } else reject(new Error(`Core repair test did not complete (exit ${code})`));
    });
  });
}
try {
  imageId = docker("image", "inspect", "lovelyres-svc:nginx", "--format", "{{.Id}}");
  const host = wsl("hostname", "-I").split(/\s+/u).find((address) => /^172\.(1[6-9]|2\d|3[01])\./u.test(address));
  if (!host) throw new Error("No private WSL address");
  containerId = docker("run", "-d", "--name", name, "--label", `lovelyres-test-run=${runId}`,
    "--memory", "384m", "--cpus", "1", "--pids-limit", "128", "-p", `${host}::22`, imageId);
  check("owned nonprivileged fixture without mounts", Boolean(owned()));
  const port = Number(owned().NetworkSettings.Ports["22/tcp"][0].HostPort);
  fixture("/tmp/lovelyres-nginx-run", runId);
  // This is the explicitly authorized disposable test environment.
  onHost("sh", "-c", "apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends python3 > /tmp/lr-python-install.log 2>&1");
  fixture("/etc/nginx/nginx.conf", `worker_processes 1;
pid /tmp/lr-nginx.pid;
error_log /tmp/lr-nginx-error.log notice;
events { worker_connections 64; }
http { include /etc/nginx/mime.types; include conf.d/lovelyres-process.conf; }
`);
  fixture("/etc/nginx/conf.d/lovelyres-process.conf", site);
  onHost("sh", "-c", "mkdir -p /tmp/lr-nginx-www/listing; printf 'safe fixture' > /tmp/lr-nginx-www/listing/item.txt");
  onHost("nginx", "-t");
  onHost("nginx");
  check("systemctl exists but systemd is not running", onHost("sh", "-c", "command -v systemctl; test ! -d /run/systemd/system && printf '%s' no-systemd").endsWith("no-systemd"));
  const inventory = invoke({ mode: "discover" });
  check("discovers one real nginx master", inventory.instances?.length === 1);
  const runtime = inventory.instances[0];
  version = runtime.version;
  check("uses build-reported config and prefix", runtime.config === "/etc/nginx/nginx.conf" && runtime.prefix === "/etc/nginx");
  check("native configuration accepted", invoke({ mode: "config-test", evidence: runtime }).verified === true);
  check("forged start time rejected", invoke({ mode: "reload", evidence: { ...runtime, start_time_ticks: runtime.start_time_ticks + 1 } }).refused === "runtime-identity-changed");
  check("forged config scope rejected", invoke({ mode: "config-test", evidence: { ...runtime, config: "/etc/nginx/conf.d/lovelyres-process.conf" } }).refused === "runtime-identity-changed");
  check("real reload verifies worker transition", invoke({ mode: "reload", evidence: runtime }).verified === true);
  const connectionId = runId;
  sidecar = new Sidecar(path.join(repository, "target/debug/lovelyhawk-backend.exe"), dataRoot);
  await connect(sidecar, { host, port, username: "root", password: "LabRoot#2026", id: connectionId, name });
  sidecar.close(); sidecar = undefined;
  owned();
  await runCargo({ LOVELYHAWK_NGINX_LAB_ROOT: dataRoot, LOVELYHAWK_NGINX_LAB_RUN: runId });
  check("real core plan confirm write verify restore suite", true);
  onHost("sh", "-c", "nginx -s quit && sleep 1");
  owned(); docker("exec", "-d", containerId, "nginx", "-g", "daemon off;");
  await new Promise((resolve) => setTimeout(resolve, 300));
  const foreground = invoke({ mode: "discover" });
  check("foreground container invocation discovered", foreground.instances?.length === 1 &&
    JSON.stringify(foreground.instances[0].arguments) === JSON.stringify(["-g", "daemon off;"]));
  check("foreground native validation and reload", invoke({ mode: "config-test", evidence: foreground.instances[0] }).verified === true &&
    invoke({ mode: "reload", evidence: foreground.instances[0] }).verified === true);
  onHost("sh", "-c", "nginx -s quit && sleep 1");
  onHost("nginx", "-c", "/etc/nginx/nginx.conf");
  check("unsupported process arguments explicitly refused", invoke({ mode: "discover" }).refused === "unsupported-master-arguments");
  onHost("sh", "-c", "nginx -s quit && sleep 1");
  fixture("/etc/nginx/conf.d/lovelyres-process.conf", site.replace("listen 127.0.0.1:8080;", "listen 127.0.0.1:8080 reuseport;"));
  onHost("nginx");
  const single = invoke({ mode: "discover" }).instances[0];
  onHost("nginx");
  check("shared configuration masters refused during discovery", invoke({ mode: "discover" }).refused === "shared-master-configuration");
  check("new shared master invalidates earlier reload authority", invoke({ mode: "reload", evidence: single }).refused === "shared-master-configuration");
  // Retained evidence identifies limits; this script is not a desktop UI test.
} catch (failure) {
  error = String(failure);
  console.error(error);
  process.exitCode = 1;
} finally {
  sidecar?.close();
  if (containerId) {
    try { owned(); docker("rm", "-f", containerId); check("owned container removed", true); }
    catch (failure) { error ??= String(failure); process.exitCode = 1; }
  }
  try {
    const resolved = fs.realpathSync(dataRoot), temp = fs.realpathSync(os.tmpdir());
    if (path.dirname(resolved) !== temp || !/^lovelyres-nginx-process-[A-Za-z0-9]{6}$/u.test(path.basename(resolved)))
      throw new Error("Unexpected fixture data root");
    fs.rmSync(resolved, { recursive: true });
    check("isolated connection and credential data removed", true);
  } catch (failure) { error ??= String(failure); process.exitCode = 1; }
  fs.writeFileSync(path.join(evidenceRoot, "report.json"), JSON.stringify({ runId, date: new Date().toISOString(),
    imageId, version, checks, error: error ?? null,
    limits: ["core repair and runtime evidence; desktop UI integration pending", "Python 3.9+, Linux pidfd, conventional default Nginx invocation", "worker transition does not establish application business health"] }, null, 2));
  console.log(evidenceRoot);
  keepalive.stdin.end();
}
