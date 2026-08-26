// Runs the exact baseline scan the tool sends inside official images, one
// version at a time, and reports what this catalogue makes of each of them.
//
// The thing that varies between versions is not the check — it is where the
// software keeps its configuration and what it does when the directive is not
// written down. A check that knows one distribution's path reports "not set"
// on every other one, and that reads as a finding rather than as a gap in the
// tool. This is how the gaps are found.
//
//   node tools/lab/verify-versions.mjs             # the whole matrix
//   node tools/lab/verify-versions.mjs mysql       # one component
//   node tools/lab/verify-versions.mjs --pull      # fetch missing images first
import { execFileSync } from "node:child_process";
import fs from "node:fs";

import path from "node:path";

// Docker Hub is not reachable from here; this mirror is.
const MIRROR = "docker.m.daocloud.io";

/**
 * The versions worth asking about.
 *
 * A database writes its real configuration when it first starts, so asking a
 * fresh image what its `postgresql.conf` says answers about a file that does
 * not exist yet. Anything with `start` is brought up the way it is meant to be
 * brought up, given time to finish initialising, and only then scanned.
 */
const MATRIX = [
  {
    component: "mysql",
    images: ["mysql:5.7", "mysql:8.0", "mysql:8.4", "mariadb:10.11", "mariadb:11"],
    start: { env: ["MYSQL_ROOT_PASSWORD=LabRoot#2026"], ready: "[ -d /var/lib/mysql/mysql ]" },
  },
  {
    component: "postgresql",
    images: ["postgres:13", "postgres:14", "postgres:16", "postgres:17"],
    start: {
      env: ["POSTGRES_PASSWORD=LabRoot#2026"],
      // Not `ls a b`: that fails when either one is missing, and it was
      // reporting every version as never having finished initialising.
      ready: "[ -f /var/lib/postgresql/data/postgresql.conf ] || [ -f /var/lib/pgsql/data/postgresql.conf ]",
    },
  },
  { component: "redis", images: ["redis:6.2", "redis:7.2", "redis:8.0"], start: { env: [], ready: "true" } },
  {
    component: "mongodb",
    images: ["mongo:5.0", "mongo:6.0", "mongo:7.0"],
    start: { env: [], ready: "true" },
  },
  { component: "nginx", images: ["nginx:1.24", "nginx:1.27"] },
  { component: "apache", images: ["httpd:2.4"] },
  { component: "tomcat", images: ["tomcat:9.0", "tomcat:10.1", "tomcat:11.0"] },
];

/**
 * Products with no official multi-version image on a registry this can reach.
 *
 * They are verified against the lab host instead, which is one real version
 * rather than none — and the lab is where their configuration was written to
 * be wrong on purpose, so the readings can be checked against something.
 */
const FROM_LABS = [
  { component: "opengauss", container: "svc-opengauss" },
  { component: "tidb", container: "svc-tidb" },
];

const args = process.argv.slice(2);
const pull = args.includes("--pull");
const only = args.find((value) => !value.startsWith("--")) ?? null;

function wsl(command, options = {}) {
  return execFileSync("wsl", ["-d", "Ubuntu", "-u", "root", "--", "sh", "-c", command], {
    encoding: "utf8",
    maxBuffer: 32 * 1024 * 1024,
    ...options,
  });
}

/** The scan script the tool sends, taken from the code that builds it. */
function scanScript() {
  const marker = "----LOVELYRES-SCAN----";
  const output = execFileSync(
    "cargo",
    ["test", "-p", "lovelyres-core", "--lib", "dump_scan_command_for_the_lab", "--", "--nocapture"],
    {
      cwd: path.resolve(path.dirname(new URL(import.meta.url).pathname.replace(/^\/([a-z]:)/iu, "$1")), "..", ".."),
      encoding: "utf8",
      maxBuffer: 64 * 1024 * 1024,
      env: { ...process.env, LOVELYRES_DUMP_SCAN: "1" },
    },
  );
  const start = output.indexOf(marker);
  const end = output.indexOf(marker, start + marker.length);
  if (start < 0 || end < 0) throw new Error("the scan dump did not come back");
  return output.slice(start + marker.length, end).trim();
}

/** Which catalogue items belong to which component, from the catalogue. */
function itemsByComponent() {
  const source = fs.readFileSync(
    path.resolve(
      path.dirname(new URL(import.meta.url).pathname.replace(/^\/([a-z]:)/iu, "$1")),
      "..", "..", "crates", "lovelyres-core", "src", "baseline.rs",
    ),
    "utf8",
  );
  const items = new Map();
  // One block at a time: the fields are not always in the same order, and a
  // window-sized regex over the whole file quietly matched only half of them.
  for (const block of source.split("BaselineDefinition {").slice(1)) {
    const body = block.slice(0, block.indexOf("\n    },"));
    const id = /\bid:\s*"([^"]+)"/u.exec(body)?.[1];
    const component = /\bcomponent:\s*BaselineComponent::(\w+)/u.exec(body)?.[1];
    const key = /\bkey:\s*"([^"]+)"/u.exec(body)?.[1];
    if (id === undefined || component === undefined || key === undefined) continue;
    items.set(id, { component: component.toLowerCase(), key });
  }
  return items;
}

/**
 * Brings the image up the way it is meant to come up, waits for it to finish
 * writing its configuration, and scans it from the inside.
 *
 * A fresh database image has no configuration file at all — it writes one on
 * first start — so scanning it cold answers about a file that is not there.
 */
function scanRunning(reference, start) {
  const name = `lovelyres-version-check`;
  wsl(`docker rm -f ${name} >/dev/null 2>&1 || true`);
  const env = start.env.map((pair) => `-e '${pair}'`).join(" ");
  wsl(`docker run -d --name ${name} -v ${inside}:/lr.sh:ro ${env} ${reference} >/dev/null`);
  try {
    let ready = false;
    for (let attempt = 0; attempt < 60; attempt += 1) {
      const answer = wsl(
        `docker exec ${name} sh -c "${start.ready.replace(/"/gu, '\\"')}" >/dev/null 2>&1 && echo yes || echo no`,
      ).trim();
      if (answer === "yes") { ready = true; break; }
      wsl("sleep 2");
    }
    if (!ready) throw new Error("容器没有在两分钟内初始化完成");
    // Let the first-start scripts finish writing before reading what they wrote.
    wsl("sleep 3");
    return wsl(`docker exec ${name} sh /lr.sh 2>/dev/null`);
  } finally {
    wsl(`docker rm -f ${name} >/dev/null 2>&1 || true`);
  }
}

const script = scanScript();
const items = itemsByComponent();
// A hundred and fifty kilobytes is far past what a command line will carry, so
// the script is written to a file, copied into the virtual machine, and
// mounted read-only into each image.
const repository = path.resolve(
  path.dirname(new URL(import.meta.url).pathname.replace(/^\/([a-z]:)/iu, "$1")),
  "..", "..",
);
fs.mkdirSync(path.join(repository, "target"), { recursive: true });
fs.writeFileSync(path.join(repository, "target", "lovelyres-scan.sh"), script.replace(/\r/gu, ""));
const inside = "/tmp/lovelyres-scan.sh";
wsl(`cp /mnt/d/LovelyRes/target/lovelyres-scan.sh ${inside} && chmod 0644 ${inside}`);
console.log(`扫描脚本 ${script.length} 字节，目录 ${items.size} 项\n`);

let gaps = 0;
for (const entry of MATRIX) {
  if (only !== null && entry.component !== only) continue;
  const wanted = [...items].filter(([, value]) => value.component === entry.component);
  console.log(`===== ${entry.component}（${wanted.length} 项检查）`);
  for (const image of entry.images) {
    const reference = `${MIRROR}/library/${image}`;
    const present = wsl(`docker image inspect ${reference} >/dev/null 2>&1 && echo yes || echo no`).trim();
    if (present !== "yes") {
      if (!pull) {
        console.log(`  ${image.padEnd(14)} 本地没有这个镜像（加 --pull 拉取）`);
        continue;
      }
      process.stdout.write(`  ${image.padEnd(14)} 拉取中…`);
      try {
        wsl(`docker pull ${reference} >/dev/null 2>&1`);
        process.stdout.write("\r");
      } catch {
        console.log(`\r  ${image.padEnd(14)} 拉不下来`);
        continue;
      }
    }
    let output;
    try {
      output = entry.start === undefined
        ? wsl(`docker run --rm -v ${inside}:/lr.sh:ro --entrypoint sh ${reference} /lr.sh 2>/dev/null`)
        : scanRunning(reference, entry.start);
    } catch (error) {
      console.log(`  ${image.padEnd(14)} 扫描没跑起来：${String(error.message).slice(0, 160)}`);
      continue;
    }
    const rows = new Map();
    for (const line of output.split(/\r?\n/u)) {
      if (!line.startsWith("ITEM=")) continue;
      const [id, value, file] = line.slice(5).split("\t");
      rows.set(id, { value, file: file ?? "" });
    }
    const absent = wanted.filter(([id]) => rows.get(id)?.value === "__absent__");
    const found = wanted.filter(([id]) => rows.get(id)?.value !== "__absent__");
    const files = new Set(found.map(([id]) => rows.get(id)?.file).filter(Boolean));
    if (absent.length === wanted.length) {
      gaps += 1;
      console.log(`  ${image.padEnd(14)} ✗ 一个配置文件都没找到 —— 这个版本的路径不在目录里`);
      continue;
    }
    console.log(`  ${image.padEnd(14)} ✓ ${found.length}/${wanted.length} 项读到，文件 ${[...files].join(" ") || "—"}`);
    for (const [id] of found) {
      const row = rows.get(id);
      console.log(`      ${id.padEnd(30)} ${row.value}`);
    }
    for (const [id] of absent) {
      console.log(`      ${id.padEnd(30)} 未找到文件`);
    }
  }
  console.log("");
}

for (const entry of FROM_LABS) {
  if (only !== null && entry.component !== only) continue;
  const wanted = [...items].filter(([, value]) => value.component === entry.component);
  console.log(`===== ${entry.component}（${wanted.length} 项检查，靶机 ${entry.container}）`);
  const running = wsl(
    `docker inspect -f '{{.State.Running}}' ${entry.container} 2>/dev/null || echo false`,
  ).trim();
  if (running !== "true") {
    console.log(`  靶机没在跑，先 pnpm lab:services\n`);
    continue;
  }
  let output;
  try {
    wsl(`docker cp ${inside} ${entry.container}:/lr.sh`);
    output = wsl(`docker exec ${entry.container} sh /lr.sh 2>/dev/null`);
  } catch (error) {
    console.log(`  扫描没跑起来：${String(error.message).slice(0, 160)}\n`);
    continue;
  }
  const rows = new Map();
  for (const line of output.split(/\r?\n/u)) {
    if (!line.startsWith("ITEM=")) continue;
    const [id, value, file] = line.slice(5).split("\t");
    rows.set(id, { value, file: file ?? "" });
  }
  const found = wanted.filter(([id]) => rows.get(id)?.value !== "__absent__");
  const files = new Set(found.map(([id]) => rows.get(id)?.file).filter(Boolean));
  if (found.length === 0) {
    gaps += 1;
    console.log(`  ✗ 一个配置文件都没找到 —— 这个版本的路径不在目录里\n`);
    continue;
  }
  console.log(`  ✓ ${found.length}/${wanted.length} 项读到，文件 ${[...files].join(" ")}`);
  for (const [id] of wanted) {
    console.log(`      ${id.padEnd(34)} ${rows.get(id)?.value ?? "—"}`);
  }
  console.log("");
}

console.log(gaps === 0 ? "每个版本都至少读到了它的配置文件" : `${gaps} 个版本一个文件都没读到`);
process.exitCode = gaps === 0 ? 0 : 1;
