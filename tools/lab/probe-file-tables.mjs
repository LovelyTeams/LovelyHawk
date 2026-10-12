// Asks each machine what it has, then asks the tool, and compares.
//
// Three tables answer the question "what is on this machine that should not
// be": setuid files, sensitive files, files changed in the last three days.
// All three were collected with `find -printf`, which **busybox does not
// have**. The error went to /dev/null and the pipeline ended in `head`, whose
// exit status is the pipeline's, so Alpine answered "command succeeded, no
// output" — and every one of those tables told the operator there was nothing
// there. A missing row is a bug; a table that says "nothing found" about a
// machine with a setuid backdoor on it is a false all-clear on the one screen
// somebody opened to find exactly that.
//
// So this probe does not check that the tables are non-empty. It counts what
// the machine itself reports and requires the tool to find the same files —
// and plants one of each first, so there is always something that must appear.
//
//   node tools/lab/probe-file-tables.mjs
//   LAB=alpine node tools/lab/probe-file-tables.mjs
import { execFileSync } from "node:child_process";

import { Sidecar, newDataRoot, connect } from "./rpc-harness.mjs";
import { labTarget } from "./lab-target.mjs";

const which = process.env.LAB ?? "ubuntu";
const container = `lab-${which}`;
const PLANTED_SUID = "/usr/local/bin/.probe-table-suid";
const PLANTED_KEY = "/root/id_rsa.probe-table";
const PLANTED_RECENT = "/tmp/.probe-table-recent";

let failures = 0;
function check(name, actual, expected = true) {
  const ok = typeof expected === "function" ? expected(actual) === true : actual === expected;
  if (!ok) failures += 1;
  console.log(`  ${ok ? "PASS" : "FAIL"} ${name}${ok ? "" : `\n       actual ${JSON.stringify(actual)}`}`);
}

function onHost(command) {
  const quoted = `'${command.replace(/'/gu, `'\\''`)}'`;
  return execFileSync(
    "wsl.exe",
    ["-d", "Ubuntu", "-u", "root", "-e", "bash", "-lc", `docker exec ${container} sh -c ${quoted}`],
    { encoding: "utf8" },
  ).split("\0").join("").trim();
}

const sidecar = new Sidecar("D:/LovelyRes/target/debug/lovelyhawk-backend.exe", newDataRoot());

async function table(binding, tab) {
  return sidecar.call("system-info.table.collect",
    { bindingHandle: binding, tab, maximumRows: 500 }, 300_000);
}

const has = (rows, needle) =>
  rows.some((row) => (row.cells ?? []).some((cell) => String(cell ?? "").includes(needle)));

try {
  console.log(`  这台机器的 find ${onHost("find /bin -maxdepth 0 -printf x >/dev/null 2>&1 && echo 支持 -printf || echo 不支持 -printf")}`);
  onHost(`mkdir -p /usr/local/bin; cp /bin/sh ${PLANTED_SUID}; chmod 4755 ${PLANTED_SUID};`
    + ` printf 'not a real key\\n' > ${PLANTED_KEY}; chmod 600 ${PLANTED_KEY};`
    + ` printf 'planted\\n' > ${PLANTED_RECENT}`);

  const status = await connect(sidecar, labTarget(which));
  if (status.stage !== "connected") throw new Error(JSON.stringify(status));
  const binding = status.bindingHandle;

  // ---- setuid ----------------------------------------------------------
  // What the machine says, asked the plainest way there is.
  const onMachine = onHost(
    "find /bin /sbin /usr/bin /usr/sbin /usr/local/bin -xdev -type f"
    + " \\( -perm -4000 -o -perm -2000 \\) 2>/dev/null | sort",
  ).split("\n").map((line) => line.trim()).filter(Boolean);
  const suid = await table(binding, "suid-files");
  console.log(`\n  setuid：机器上有 ${onMachine.length} 个，表里列出 ${suid.rows.length} 行`);
  check("表不该在有 setuid 文件的机器上说没有", suid.rows.length > 0);
  check("我们种的那个在表里", has(suid.rows, ".probe-table-suid"));
  // Every file the machine named has to be in the table. A tool that finds
  // some of them is worse than one that finds none, because it looks like it
  // worked.
  const missed = onMachine.filter((path) => !has(suid.rows, path));
  if (missed.length > 0) console.log(`  漏掉的：${missed.slice(0, 5).join(", ")}`);
  check("机器上每一个 setuid 文件都在表里", missed.length, 0);
  // The columns have to carry facts, not blanks.
  const plantedRow = suid.rows.find((row) =>
    (row.cells ?? []).some((cell) => String(cell ?? "").includes(".probe-table-suid")));
  console.log(`  那一行：${JSON.stringify(plantedRow?.cells)}`);
  check("权限列是真的权限", plantedRow?.cells?.[1], "4755");
  check("属主列有名字", plantedRow?.cells?.[2], (value) => String(value ?? "").length > 0);
  check("大小列是个数", plantedRow?.cells?.[3], (value) => Number(value) > 0);
  check("时间列是能读的日期", plantedRow?.cells?.[4],
    (value) => /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$/u.test(String(value ?? "")));

  // ---- sensitive files -------------------------------------------------
  const sensitive = await table(binding, "sensitive");
  console.log(`\n  敏感文件：表里列出 ${sensitive.rows.length} 行`);
  check("表不该说没有（/etc/shadow 总在）", sensitive.rows.length > 0);
  check("我们种的那把私钥在表里", has(sensitive.rows, "id_rsa.probe-table"));
  check("/etc/shadow 也在", has(sensitive.rows, "shadow"));
  const keyRow = sensitive.rows.find((row) =>
    (row.cells ?? []).some((cell) => String(cell ?? "").includes("id_rsa.probe-table")));
  console.log(`  那一行：${JSON.stringify(keyRow?.cells)}`);
  check("权限列是真的权限", keyRow?.cells?.[2], "600");
  check("时间列是能读的日期", keyRow?.cells?.[4],
    (value) => /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$/u.test(String(value ?? "")));

  // ---- recently changed ------------------------------------------------
  const recent = await table(binding, "recent-files");
  console.log(`\n  最近改过的文件：表里列出 ${recent.rows.length} 行`);
  check("表不该说没有（刚种了一个）", recent.rows.length > 0);
  check("刚种下的那个在表里", has(recent.rows, ".probe-table-recent"));
  const recentRow = recent.rows.find((row) =>
    (row.cells ?? []).some((cell) => String(cell ?? "").includes(".probe-table-recent")));
  console.log(`  那一行：${JSON.stringify(recentRow?.cells)}`);
  check("时间列是能读的日期", recentRow?.cells?.[1],
    (value) => /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$/u.test(String(value ?? "")));
  check("大小列是个数", recentRow?.cells?.[2], (value) => Number(value) >= 0);
  check("属主列有名字", recentRow?.cells?.[3], (value) => String(value ?? "").length > 0);

  // A name containing the separator the command uses internally must not
  // split a row in half or lose the file.
  const awkward = "/tmp/.probe-table|pipe|name";
  onHost(`printf 'awkward\\n' > '${awkward}'`);
  const again = await table(binding, "recent-files");
  console.log(`\n  名字里带竖线的文件：${has(again.rows, ".probe-table|pipe|name") ? "整条还在" : "没找到或被截断"}`);
  check("名字里带竖线也不会被切开", has(again.rows, ".probe-table|pipe|name"));
  onHost(`rm -f '${awkward}'`);
} catch (error) {
  console.log(`\nFAILED: ${error.message}`);
  const stderr = sidecar.stderr.join("").trim();
  if (stderr !== "") console.log(stderr.slice(-700));
  failures += 1;
} finally {
  sidecar.close();
  try { onHost(`rm -f ${PLANTED_SUID} ${PLANTED_KEY} ${PLANTED_RECENT} '/tmp/.probe-table|pipe|name'`); } catch {}
}

console.log(`\n${failures === 0 ? "ALL CHECKS PASSED" : `${failures} CHECK(S) FAILED`}`);
process.exitCode = failures === 0 ? 0 : 1;
