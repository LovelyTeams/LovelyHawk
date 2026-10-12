// Real native PostgreSQL authentication and lifecycle through the core SSH actor.
// Without --desktop this does not claim the desktop database page; it never claims production database writes.
import { execFileSync, spawn } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Sidecar, connect, backendBinary } from "./rpc-harness.mjs";

const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const desktop = process.argv.includes("--desktop");
const runId = randomUUID(), deniedId = randomUUID(), name = `lr-pg-native-${runId.slice(0, 8)}`;
const evidence = path.join(repository, desktop ? "target/lab-postgresql-desktop" : "target/lab-postgresql-native", runId);
const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "lovelyhawk-pg-native-"));
const pgdata = "/var/lib/postgresql/data";
const password = "Lab'\"Native中#2026"; // Fixture canary, never a user credential.
const checks = [], observations = {}, accessCanaries = [];
const registerAccessCanary = value => {
  if (accessCanaries.length !== 0 || typeof value !== "string" || !/^lr-auth-secret-[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/u.test(value)) throw new Error("Unexpected owned access canary");
  accessCanaries.push(value);
};
let containerId, imageId, version, platform, sidecar, failure;
fs.mkdirSync(evidence, { recursive: true });
const keepalive = spawn("wsl.exe", ["-d", "Ubuntu", "-u", "root", "--", "cat"], { windowsHide: true, stdio: ["pipe", "ignore", "ignore"] });
keepalive.once("error", error => { failure ??= String(error); });
const wsl = (...args) => execFileSync("wsl.exe", ["-d", "Ubuntu", "-u", "root", "--", ...args], { encoding: "utf8", windowsHide: true, timeout: 60_000, maxBuffer: 2 * 1024 * 1024 }).trim();
const docker = (...args) => wsl("docker", ...args);
function check(label, actual) { checks.push({ label, passed: Boolean(actual) }); console.log(`${actual ? "PASS" : "FAIL"} ${label}`); if (!actual) throw new Error(label); }
function owned() {
  const target = JSON.parse(docker("inspect", containerId))[0];
  if (target.Id !== containerId || target.Image !== imageId || target.Name !== `/${name}` || target.Config.Labels?.["lovelyres-test-run"] !== runId ||
    target.HostConfig.Privileged || target.HostConfig.NetworkMode !== "bridge" || target.Mounts.some(mount => mount.Type !== "tmpfs" || mount.Destination !== pgdata) ||
    target.HostConfig.Tmpfs?.[pgdata] !== "rw,noexec,nosuid,size=256m" || target.HostConfig.Memory !== 512 * 1024 * 1024 ||
    target.HostConfig.NanoCpus !== 1_000_000_000 || target.HostConfig.PidsLimit !== 128 || target.HostConfig.PidMode !== "" || JSON.stringify((target.HostConfig.CapAdd ?? []).map(cap => cap.replace(/^CAP_/u, ""))) !== JSON.stringify(desktop ? ["SYS_PTRACE"] : [])) throw new Error("Owned PostgreSQL fixture identity or resource limits changed");
  return target;
}
const onHost = (...args) => { owned(); return docker("exec", containerId, ...args); };
function script(input) {
  owned();
  return execFileSync("wsl.exe", ["-d", "Ubuntu", "-u", "root", "--", "docker", "exec", "-i", containerId, "sh", "-se"],
    { input, encoding: "utf8", windowsHide: true, timeout: 60_000, maxBuffer: 2 * 1024 * 1024 }).trim();
}
const sql = statement => onHost("runuser", "-u", "postgres", "--", "psql", "-X", "-w", "-At", "-v", "ON_ERROR_STOP=1", "-d", "postgres", "-c", statement);
async function until(fn) {
  const end = Date.now() + 60_000;
  while (Date.now() < end) { try { if (fn()) return; } catch {} await new Promise(resolve => setTimeout(resolve, 250)); }
  throw new Error("Owned PostgreSQL startup timed out");
}
async function coreSuite() {
  await new Promise((resolve, reject) => {
    let transcript = "";
    const child = spawn("cargo", ["test", "--locked", "--package", "lovelyhawk-core", "postgresql_native::lab::owned_postgresql_native_runtime", "--lib", "--", "--ignored", "--exact", "--nocapture"],
      { cwd: repository, windowsHide: true, env: { ...process.env, LOVELYHAWK_PG_NATIVE_ROOT: dataRoot, LOVELYHAWK_PG_NATIVE_RUN: runId, LOVELYHAWK_PG_NATIVE_NO_FORWARD: deniedId } });
    const log = fs.createWriteStream(path.join(evidence, "core-native.log"));
    const timer = setTimeout(() => { child.kill(); reject(new Error("Owned native core suite exceeded four minutes")); }, 240_000);
    child.stdout.on("data", chunk => { transcript += chunk.toString(); log.write(chunk); process.stdout.write(chunk); });
    child.stderr.on("data", chunk => { log.write(chunk); process.stdout.write(chunk); });
    child.once("error", error => { clearTimeout(timer); log.end(); reject(error); });
    child.once("close", code => {
      clearTimeout(timer); log.end();
      for (const line of transcript.split(/\r?\n/u)) if (line.startsWith("POSTGRESQL_NATIVE_CHECK ")) checks.push({ label: line.slice("POSTGRESQL_NATIVE_CHECK ".length), passed: true });
      if (code === 0 && transcript.includes("POSTGRESQL_NATIVE_SUITE_COMPLETE") && transcript.includes("1 passed; 0 failed")) resolve();
      else reject(new Error(`Owned native core suite failed (exit ${code})`));
    });
  });
}
function valueHasCanary(value) {
  if (typeof value === "string") return value.includes(password) || value.includes(JSON.stringify(password).slice(1, -1));
  if (Array.isArray(value)) return value.some(valueHasCanary);
  return value !== null && typeof value === "object" && Object.entries(value).some(([key, item]) => valueHasCanary(key) || valueHasCanary(item));
}
function bytesHaveCanary(bytes) {
  const text = bytes.toString("utf8");
  if (valueHasCanary(text)) return true;
  try { return valueHasCanary(JSON.parse(text)); } catch { return false; }
}
function plaintextHasCanary(directory, predicate = bytesHaveCanary) {
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    const file = path.join(directory, entry.name);
    if (entry.isSymbolicLink()) throw new Error("Unexpected symbolic link in isolated application data");
    if (entry.isDirectory() ? plaintextHasCanary(file, predicate) : predicate(fs.readFileSync(file))) return true;
  }
  return false;
}

try {
  check("password absence checks also detect quoted and Unicode-escaped JSON credentials", bytesHaveCanary(Buffer.from(JSON.stringify({ nested: [password] }).replaceAll("中", "\\u4e2d"))) && !bytesHaveCanary(Buffer.from('{"nested":["unrelated"]}')));
  imageId = docker("image", "inspect", "lovelyres-svc:postgres", "--format", "{{.Id}}");
  const host = wsl("hostname", "-I").split(/\s+/u).find(ip => /^172\.(1[6-9]|2\d|3[01])\.\d+\.\d+$/u.test(ip));
  if (!host) throw new Error("Missing private WSL address");
  containerId = docker("run", "-d", "--name", name, "--label", `lovelyres-test-run=${runId}`, "--memory", "512m", "--cpus", "1", "--pids-limit", "128", ...(desktop ? ["--cap-add", "SYS_PTRACE"] : []), "--tmpfs", `${pgdata}:rw,noexec,nosuid,size=256m`,
    "-p", `${host}::22`, "-p", `${host}::2222`, "-e", "POSTGRES_PASSWORD=LabDb#2026", "-e", "LAB_SERVICE_COMMAND=/usr/local/bin/docker-entrypoint.sh postgres", imageId);
  check("native fixture uses bounded resources and only its own container storage", Boolean(owned()));
  await until(() => sql("SELECT 1") === "1");
  version = onHost("postgres", "--version"); platform = onHost("sh", "-c", "cat /etc/os-release; uname -m");
  if (desktop) {
    script("if ! command -v python3 >/dev/null; then timeout 45s sh -c 'apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends python3' >/tmp/lr-pg-python-install.log 2>&1; fi\n");
    observations.python = onHost("python3", "--version");
    check("only the owned desktop fixture receives Python and same-container process inspection capability", /^Python 3\./u.test(observations.python) && owned().HostConfig.CapAdd.length === 1);
  }
  observations.openssl = onHost("openssl", "version");
  script(`
printf '%s' '${runId}' > /tmp/lovelyres-pg-native-run
cd ${pgdata}
openssl req -new -x509 -newkey rsa:2048 -nodes -keyout fixture-ca.key -out fixture-ca.pem -days 2 -subj /CN=LovelyHawkOwnedCA -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign >/dev/null 2>&1
openssl req -new -x509 -newkey rsa:2048 -nodes -keyout fixture-other-ca.key -out fixture-other-ca.pem -days 2 -subj /CN=LovelyHawkOtherCA -addext basicConstraints=critical,CA:TRUE >/dev/null 2>&1
openssl req -new -newkey rsa:2048 -nodes -keyout fixture-server.key -out fixture-server.csr -subj /CN=127.0.0.1 >/dev/null 2>&1
printf 'subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\n' > fixture-server.ext
openssl x509 -req -in fixture-server.csr -CA fixture-ca.pem -CAkey fixture-ca.key -CAcreateserial -out fixture-server.pem -days 2 -extfile fixture-server.ext >/dev/null 2>&1
chown postgres:postgres fixture-server.key fixture-server.pem
chmod 600 fixture-server.key
runuser -u postgres -- psql -X -w -v ON_ERROR_STOP=1 -d postgres <<'SQL'
SET password_encryption = 'scram-sha-256';
CREATE ROLE lr_scram LOGIN SUPERUSER PASSWORD 'Lab''"Native中#2026';
CREATE ROLE lr_denied LOGIN PASSWORD 'Lab''"Native中#2026';
SET password_encryption = 'md5';
CREATE ROLE lr_md5 LOGIN SUPERUSER PASSWORD 'Lab''"Native中#2026';
REVOKE SELECT ON pg_catalog.pg_settings FROM PUBLIC;
ALTER SYSTEM SET ssl = 'on';
ALTER SYSTEM SET ssl_cert_file = '${pgdata}/fixture-server.pem';
ALTER SYSTEM SET ssl_key_file = '${pgdata}/fixture-server.key';
ALTER SYSTEM SET log_connections = 'on';
ALTER SYSTEM SET log_disconnections = 'on';
SQL
cat > pg_hba.conf <<'HBA'
local all all trust
host all lr_scram 127.0.0.0/8 scram-sha-256
host all lr_scram ::1/128 scram-sha-256
host all lr_md5 127.0.0.0/8 md5
host all lr_denied 127.0.0.0/8 scram-sha-256
host all all 0.0.0.0/0 reject
host all all ::0/0 reject
HBA
chown postgres:postgres pg_hba.conf
runuser -u postgres -- psql -X -w -At -v ON_ERROR_STOP=1 -d postgres -c 'SELECT pg_reload_conf()'
/usr/sbin/sshd -p 2222 -o AllowTcpForwarding=no
`);
  await until(() => sql("SHOW ssl") === "on");
  // WSL can run ahead of the Windows clock. Do not weaken certificate checks
  // or change either system clock: wait until these new certificates are valid
  // for the actual Windows client, and preserve that precondition as evidence.
  observations.certificateNotBefore = ["fixture-ca.pem", "fixture-other-ca.pem", "fixture-server.pem"].map(file =>
    onHost("openssl", "x509", "-in", `${pgdata}/${file}`, "-noout", "-startdate").replace(/^notBefore=/u, ""));
  const validFrom = Math.max(...observations.certificateNotBefore.map(value => Date.parse(value)));
  if (!Number.isFinite(validFrom)) throw new Error("Cannot determine fixture certificate validity");
  observations.clientTimeBeforeValidityWait = new Date().toISOString();
  await until(() => Date.now() >= validFrom);
  check("all fixture certificates are valid at the Windows client clock", Date.now() >= validFrom);
  observations.roleVerifiers = sql("SELECT rolname || ':' || CASE WHEN rolpassword LIKE 'SCRAM-SHA-256$%' THEN 'scram-sha-256' WHEN rolpassword LIKE 'md5%' THEN 'md5' ELSE 'unexpected' END FROM pg_authid WHERE rolname IN ('lr_scram','lr_md5') ORDER BY rolname");
  observations.sslMaxProtocol = JSON.parse(sql("SELECT json_build_object('setting',setting,'enumvals',enumvals) FROM pg_settings WHERE name = 'ssl_max_protocol_version'"));
  observations.independentBaseSessionQuery = JSON.parse(Buffer.from(sql(fs.readFileSync(path.join(repository, "crates/lovelyhawk-core/src/postgresql_observation.sql"), "utf8")), "hex").toString("utf8"));
  check("native PostgreSQL exposes a valid empty SSL maximum protocol enum option", observations.sslMaxProtocol.setting === "" && observations.sslMaxProtocol.enumvals.includes(""));
  check("independent PostgreSQL catalog confirms distinct SCRAM and MD5 fixture verifiers", observations.roleVerifiers === "lr_md5:md5\nlr_scram:scram-sha-256");
  fs.writeFileSync(path.join(dataRoot, "fixture-ca.pem"), onHost("cat", `${pgdata}/fixture-ca.pem`));
  fs.writeFileSync(path.join(dataRoot, "fixture-other-ca.pem"), onHost("cat", `${pgdata}/fixture-other-ca.pem`));
  sidecar = new Sidecar(path.resolve(repository, backendBinary()), dataRoot);
  for (const [id, port] of [[runId, "22/tcp"], [deniedId, "2222/tcp"]]) {
    const status = await connect(sidecar, { host, port: Number(owned().NetworkSettings.Ports[port][0].HostPort), username: "root", password: "LabRoot#2026", id, name: `${name}-${port}` });
    check(`owned SSH fixture ${port} is saved with a confirmed host key`, status?.stage === "connected");
  }
  sidecar.close(); sidecar = undefined;
  owned();
  if (desktop) {
    await new Promise(resolve => setTimeout(resolve, 300));
    const { desktopScenario } = await import("./postgresql-desktop-scenario.mjs");
    await desktopScenario({ repository, dataRoot, evidence, name, password, check, sql, script, observations, registerAccessCanary });
  } else await coreSuite();
  // The desktop app's live instance lock (and WebView2's profile) is readable only after its processes exit.
  // Keep this nonce outside observations so it cannot be serialized on failure.
  if (desktop) check("all owned portable files exclude the authentication option and error canary after the desktop app exits", accessCanaries.length === 1 && !plaintextHasCanary(dataRoot, bytes => accessCanaries.some(secret => bytes.includes(Buffer.from(secret)))));
  check("portable data does not contain the native password canary", !plaintextHasCanary(dataRoot));
  const serviceLog = onHost("tail", "-n", "1500", "/var/log/lab-service.log");
  fs.writeFileSync(path.join(evidence, "service-log.txt"), serviceLog);
  check("server evidence contains actual SCRAM and MD5 authentication", /method=scram-sha-256/u.test(serviceLog) && /method=md5/u.test(serviceLog));
  check("server evidence contains a TLS connection for the native application", /application_name=LovelyHawk runtime review SSL enabled/u.test(serviceLog));
  check("native password stays absent from server and test output", !bytesHaveCanary(Buffer.from(serviceLog)) && (desktop ? !valueHasCanary({ observations, checks }) : !bytesHaveCanary(fs.readFileSync(path.join(evidence, "core-native.log")))));
  check("independent final query finds no native database sessions", sql("SELECT count(*) FROM pg_stat_activity WHERE application_name = 'LovelyHawk runtime review'") === "0");
} catch (error) { failure = String(error); console.error(failure); process.exitCode = 1; }
finally {
  sidecar?.close();
  if (containerId) {
    try { fs.writeFileSync(path.join(evidence, "service-log.txt"), onHost("tail", "-n", "1500", "/var/log/lab-service.log")); } catch {}
    if (desktop) for (const file of ["lr-pg-python-install.log", "lr-pg-process-session-error.log"]) {
      try { fs.writeFileSync(path.join(evidence, file), onHost("cat", `/tmp/${file}`)); } catch {}
    }
    try { owned(); docker("rm", "-f", containerId); check("owned native PostgreSQL container removed", true); } catch (error) { failure ??= String(error); process.exitCode = 1; }
  }
  try {
    const resolved = fs.realpathSync(dataRoot), temp = fs.realpathSync(os.tmpdir());
    if (path.dirname(resolved) !== temp || !/^lovelyhawk-pg-native-[A-Za-z0-9]{6}$/u.test(path.basename(resolved))) throw new Error("Unexpected fixture data root");
    fs.rmSync(resolved, { recursive: true, maxRetries: 10, retryDelay: 300 }); check("isolated application data and fixture public certificates removed", true);
  } catch (error) { failure ??= String(error); process.exitCode = 1; }
  const sourceHashes = Object.fromEntries(["crates/lovelyhawk-core/src/postgresql_objects.rs","crates/lovelyhawk-core/src/postgresql_objects_columns.sql","crates/lovelyhawk-core/src/postgresql_objects_database.sql","crates/lovelyhawk-core/src/postgresql_objects_defaults.sql","crates/lovelyhawk-core/src/postgresql_objects_foreign_servers.sql","crates/lovelyhawk-core/src/postgresql_objects_foreign_wrappers.sql","crates/lovelyhawk-core/src/postgresql_objects_languages.sql","crates/lovelyhawk-core/src/postgresql_objects_large_objects.sql","crates/lovelyhawk-core/src/postgresql_objects_parameters.sql","crates/lovelyhawk-core/src/postgresql_objects_permissions.sql","crates/lovelyhawk-core/src/postgresql_objects_relations.sql","crates/lovelyhawk-core/src/postgresql_objects_routines.sql","crates/lovelyhawk-core/src/postgresql_objects_schemas.sql","crates/lovelyhawk-core/src/postgresql_objects_tablespaces.sql","crates/lovelyhawk-core/src/postgresql_objects_types.sql", "tools/lab/probe-postgresql-native.mjs", "crates/lovelyhawk-core/src/postgresql_access.rs", "crates/lovelyhawk-core/src/postgresql_role_graph.rs", "crates/lovelyhawk-core/src/postgresql_access_memberships.sql", "crates/lovelyhawk-core/src/postgresql_access_database.sql", "crates/lovelyhawk-core/src/postgresql_access_permissions.sql", "crates/lovelyhawk-core/src/postgresql_access_hba.sql", "crates/lovelyhawk-core/src/postgresql_access_ident.sql", "crates/lovelyhawk-core/src/postgresql_access_roles.sql", "crates/lovelyhawk-core/src/postgresql_access_roles_private.sql", "crates/lovelyhawk-core/src/postgresql_observation.rs", "crates/lovelyhawk-core/src/postgresql_process.rs", "crates/lovelyhawk-core/src/postgresql_process.py", "crates/lovelyhawk-core/src/postgresql_observation.sql", "crates/lovelyhawk-core/src/postgresql_native.rs", "crates/lovelyhawk-core/src/postgresql_wire.rs", "crates/lovelyhawk-core/src/postgresql_native_lab.rs", "crates/lovelyhawk-core/src/database.rs", "crates/lovelyhawk-core/src/database_config_runtime.rs", "crates/lovelyhawk-core/src/ssh.rs", "Cargo.toml", "crates/lovelyhawk-core/Cargo.toml", "Cargo.lock", ...(desktop ? ["tools/lab/postgresql-object-scenario.mjs", "ui/src/shared/postgresql-object-contract.ts", "ui/src/renderer/PostgresqlObjectPanel.tsx", "tools/lab/postgresql-role-scenario.mjs", "ui/src/shared/postgresql-role-contract.ts", "ui/src/renderer/PostgresqlRolePanel.tsx", "tools/lab/postgresql-access-scenario.mjs", "ui/src/shared/postgresql-access-contract.ts", "ui/src/renderer/PostgresqlAccessPanel.tsx", "tools/lab/postgresql-observation-scenario.mjs", "tools/lab/postgresql-process-scenario.mjs", "tools/lab/test_postgresql_process.py", "ui/src/renderer/PostgresqlHostProcessPanel.tsx", "tools/lab/postgresql-desktop-scenario.mjs", "tools/lab/desktop.mjs", "crates/lovelyhawk-backend/src/postgresql_runtime_api.rs", "crates/lovelyhawk-backend/src/lib.rs", "ui/src/shared/postgresql-runtime-contract.ts", "ui/src/host/main-api.ts", "crates/lovelyhawk-desktop/src/backend_bridge.rs", "ui/src/host/backend-client.ts", "ui/src/renderer/DatabasePage.tsx", "ui/src/renderer/postgresql-runtime-controller.ts", "ui/src/renderer/database-page.css"] : [])].map(file => [file, createHash("sha256").update(fs.readFileSync(path.join(repository, file))).digest("hex")]));
  fs.writeFileSync(path.join(evidence, "report.json"), JSON.stringify({ runId, date: new Date().toISOString(), imageId, version, platform, sourceHashes, observations, checks, error: failure ?? null,
    limits: [desktop ? "normal desktop (Tauri / WebView2) and native API acceptance; no database mutation feature claimed" : "core integration; no desktop database UI or RPC acceptance claim", "only PostgreSQL 16 fixture on this OS/architecture is real tested", "transport drop does not send a PostgreSQL CancelRequest; lock and statement timeouts bound server work", "runtime rows are server/session observations, not full instance/configuration identity or business health", "library-owned authentication buffers are not guaranteed to be zeroized", "fixture writes are not product repair behavior"] }, null, 2));
  console.log(`Evidence: ${path.join(evidence, "report.json")}`); keepalive.stdin.end();
}
