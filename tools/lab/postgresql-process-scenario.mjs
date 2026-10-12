// Actual product observation plus independent, owned-fixture kernel checks.
import fs from "node:fs";
import { createHash } from "node:crypto";

export async function processScenario({ current, read, lastJob, script, sql, page, check, until, observations }) {
  const process = current.result.hostProcess;
  observations.hostProcess = process;
  const independent = JSON.parse(script(`python3 -I - <<'PY'
import hashlib,json,os
pid=int(open('/var/lib/postgresql/data/postmaster.pid').readline())
base='/proc/%d/'%pid
print(json.dumps({'pid':pid,'exe':os.readlink(base+'exe'),'sha256':hashlib.sha256(open(base+'exe','rb').read()).hexdigest(),'cwd':os.readlink(base+'cwd'),'bootId':open('/proc/sys/kernel/random/boot_id').read().strip(),'namespaces':{n:str(os.stat(base+'ns/'+n).st_ino) for n in ['pid','net','mnt']}}))
PY
`));
  observations.independentHostProcess = independent;
  check("the live native connection correlates with the independently observed PostgreSQL parent and executable", process.state === "matched" && process.process.backendPid === current.result.session.backendPid && process.process.postmasterPid === independent.pid && process.process.executablePath === independent.exe && process.process.executableSha256 === independent.sha256 && process.process.dataDirectory === independent.cwd && process.process.reportedDirectoryMatches && process.process.bootId === independent.bootId);
  check("reported process namespaces match the owned container's independent procfs observations", process.process.pidNamespace === independent.namespaces.pid && process.process.networkNamespace === independent.namespaces.net && process.process.mountNamespace === independent.namespaces.mnt);
  await page.evaluate("document.querySelector('.database-host-process details').open=true;document.querySelector('.database-host-process').scrollIntoView({block:'start'})");
  await page.shot("postgresql-host-process-1080x700.png");
  const code = fs.readFileSync(new URL("../../crates/lovelyhawk-core/src/postgresql_process.py", import.meta.url)).toString("base64");
  script("sed -i '1ihostssl postgres postgres 127.0.0.1/32 scram-sha-256' /var/lib/postgresql/data/pg_hba.conf\n");
  sql("SELECT pg_reload_conf()");
  script(`test ! -e /tmp/lr-pg-process-probe.py
printf '%s' '${code}' | base64 -d > /tmp/lr-pg-process-probe.py
chmod 644 /tmp/lr-pg-process-probe.py
cat > /tmp/lr-pg-process-query.sql <<'SQL'
SELECT json_build_object('backendPid',pg_backend_pid(),'serverAddress',host(inet_server_addr()),'serverPort',inet_server_port(),'clientAddress',host(inet_client_addr()),'clientPort',inet_client_port(),'dataDirectory',current_setting('data_directory'));
SELECT pg_sleep(60);
SQL
chmod 644 /tmp/lr-pg-process-query.sql
runuser -u postgres -- env PGPASSWORD=LabDb#2026 PGAPPNAME=LovelyHawk_owned_process psql -X -A -t -w -h 127.0.0.1 -U postgres -d postgres -f /tmp/lr-pg-process-query.sql >/tmp/lr-pg-process-session.json 2>/tmp/lr-pg-process-session-error.log &
`);
  let input;
  await until(() => {
    const text = script("if [ -s /tmp/lr-pg-process-session-error.log ]; then printf 'fixture-session-error'; else head -n 1 /tmp/lr-pg-process-session.json; fi");
    if (text === "fixture-session-error") throw Error("Independent PostgreSQL session failed; see fixture session log");
    if (!text) return false;
    input = JSON.parse(text); return input.backendPid > 0;
  }, "independent live TCP PostgreSQL session");
  const invoke = (payload, user = "root") => JSON.parse(script(`runuser -u ${user} -- python3 -I /tmp/lr-pg-process-probe.py <<'INPUT'
${JSON.stringify(payload)}
INPUT
`));
  check("the closed helper also matches an independently held TCP session", invoke(input).state === "matched");
  check("the helper refuses another port and a parent PID that does not own the connected socket", invoke({ ...input, clientPort: input.clientPort % 65535 + 1 }).reason === "socket-unmatched" && invoke({ ...input, backendPid: independent.pid }).reason === "socket-unmatched");
  check("an unprivileged SSH-equivalent account retains a process permission refusal", invoke(input, "nobody").reason === "permission-denied");
  const wrapper = "#!/bin/sh\n# LovelyHawk owned missing dependency fixture\nexit 127\n";
  const hash = createHash("sha256").update(wrapper).digest("hex");
  script(`test ! -e /usr/local/bin/python3 && test ! -L /usr/local/bin/python3
printf '%s' '${Buffer.from(wrapper).toString("base64")}' | base64 -d > /usr/local/bin/python3
chmod 755 /usr/local/bin/python3
test "$(command -v python3)" = /usr/local/bin/python3
`);
  try {
    await read(); const missing = await lastJob();
    check("missing target tooling leaves real runtime values readable and the process gap visible in the desktop page", missing.state === "completed" && missing.result.hostProcess.state === "unavailable" && missing.result.hostProcess.reason === "unsupported" && await page.evaluate("document.querySelector('.database-host-process').textContent.includes('未自动安装')&&document.querySelector('.database-host-process').textContent.includes('参数仍可独立查看')"));
    await page.evaluate("document.querySelector('.database-host-process').scrollIntoView({block:'start'})"); await page.shot("postgresql-host-process-unavailable.png");
  } finally {
    script(`test "$(sha256sum /usr/local/bin/python3 | cut -d' ' -f1)" = '${hash}'
rm /usr/local/bin/python3
`);
  }
  sql(`SELECT pg_cancel_backend(pid) FROM pg_stat_activity WHERE pid=${input.backendPid} AND application_name='LovelyHawk_owned_process' AND usename='postgres' AND datname='postgres' AND client_addr='127.0.0.1' AND client_port=${input.clientPort}`);
  await until(() => sql("SELECT count(*) FROM pg_stat_activity WHERE application_name='LovelyHawk_owned_process'") === "0", "owned independent process session finishes");
}
