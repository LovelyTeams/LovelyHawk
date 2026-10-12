// Checks that each service lab is reachable over SSH and that the deliberate
// misconfiguration is where LovelyHawk will look for it.
//
//   node tools/lab/verify-services.mjs
import { execFileSync } from "node:child_process";

import { Sidecar, newDataRoot, connect } from "./rpc-harness.mjs";
import { SERVICE_PORTS } from "./lab-target.mjs";

/** What has to be true on each host for the lab to be worth connecting to. */
const EXPECTED = {
  nginx: { file: "/etc/nginx/nginx.conf", contains: "server_tokens on" },
  httpd: { file: "/usr/local/apache2/conf/httpd.conf", contains: "ServerTokens Full" },
  tomcat: { file: "/usr/local/tomcat/conf/tomcat-users.xml", contains: 'password="tomcat"' },
  mysql: { file: "/etc/my.cnf", contains: "local_infile = ON" },
  mariadb: { file: "/etc/mysql/mariadb.conf.d/99-lab.cnf", contains: "bind-address = 0.0.0.0" },
  postgres: { file: "/docker-entrypoint-initdb.d/00-lab.sh", contains: "listen_addresses = '*'" },
  redis: { file: "/etc/redis/redis.conf", contains: "protected-mode no" },
  mongo: { file: "/etc/mongod.conf", contains: "authorization: disabled" },
  opengauss: { file: "/opt/lab/misconfigure-late.sh", contains: "audit_enabled = off" },
  tidb: { file: "/etc/tidb/tidb.toml", contains: "skip-grant-table = true" },
};

function onHost(container, command) {
  try {
    return execFileSync(
      "wsl.exe",
      ["-d", "Ubuntu", "-u", "root", "-e", "bash", "-lc",
        `docker exec ${container} sh -c ${JSON.stringify(command)}`],
      { encoding: "utf8" },
    ).split("\0").join("").trim();
  } catch {
    return "";
  }
}

function wslAddress() {
  const output = execFileSync("wsl.exe", ["-d", "Ubuntu", "-e", "bash", "-lc", "hostname -I"], {
    encoding: "utf8",
  });
  return output.split("\0").join("").trim().split(/\s+/u)[0];
}

let failures = 0;
const host = wslAddress();
console.log(`靶机地址 ${host}\n`);

for (const [name, port] of Object.entries(SERVICE_PORTS)) {
  const container = `svc-${name}`;
  const expected = EXPECTED[name];
  const running = onHost(container, "echo up") === "up";
  const sshd = onHost(container, "pgrep -x sshd >/dev/null && echo yes || echo no") === "yes";
  const planted = expected === undefined
    ? true
    : onHost(container, `grep -qF ${JSON.stringify(expected.contains)} ${expected.file} && echo yes || echo no`) === "yes";

  const sidecar = new Sidecar("D:/LovelyRes/target/debug/lovelyhawk-backend.exe", newDataRoot());
  let reachable = false;
  try {
    const status = await connect(sidecar, { host, port, username: "root", password: "LabRoot#2026" }, 2);
    reachable = status?.stage === "connected";
  } catch {
    reachable = false;
  } finally {
    sidecar.close();
  }

  const ok = running && sshd && planted && reachable;
  if (!ok) failures += 1;
  console.log(
    `  ${ok ? "PASS" : "FAIL"} ${name.padEnd(10)} :${port}  ` +
    `容器${running ? "✓" : "✗"} sshd${sshd ? "✓" : "✗"} ` +
    `配置${planted ? "✓" : "✗"} 可连${reachable ? "✓" : "✗"}`,
  );
  if (!ok && expected !== undefined && !planted) {
    console.log(`       期望 ${expected.file} 里有 ${JSON.stringify(expected.contains)}`);
  }
}

console.log(`\n${failures === 0 ? "全部就绪" : `${failures} 台未就绪`}`);
process.exitCode = failures === 0 ? 0 : 1;
