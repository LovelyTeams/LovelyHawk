// Asks a machine that has more rows than the table can show whether the table
// admits it.
//
// Every tab caps its own output on the target. While that cap equalled the
// number of rows the caller wanted, a busy machine answered with a full table
// and nothing else — so the window showed five hundred processes and reported
// that nothing had been cut. The process worth finding on a compromised host is
// exactly the one that would sit past the cap.
//
//   node tools/lab/probe-table-truncation.mjs
//   LAB=rocky node tools/lab/probe-table-truncation.mjs
import { execFileSync } from "node:child_process";

import { Sidecar, newDataRoot, connect } from "./rpc-harness.mjs";
import { labTarget } from "./lab-target.mjs";

const which = process.env.LAB ?? "ubuntu";
const container = `lab-${which}`;
/** Comfortably past the five hundred rows the window asks for. */
const PLANTED = 560;
const PID_FILE = "/tmp/lovelyres-truncation-probe.pids";

let failures = 0;
function check(name, actual, expected = true) {
  const ok = actual === expected;
  if (!ok) failures += 1;
  console.log(`  ${ok ? "PASS" : "FAIL"} ${name}${ok ? "" : `\n       expected ${JSON.stringify(expected)}\n       actual   ${JSON.stringify(actual)}`}`);
}

function onHost(command) {
  // Single-quoted for the outer shell: double quotes let it expand `$i` before
  // the container ever sees the loop, which turned the planting step into
  // `[: -lt: unexpected operator` and quietly planted nothing.
  const quoted = `'${command.replace(/'/gu, `'\\''`)}'`;
  return execFileSync(
    "wsl.exe",
    ["-d", "Ubuntu", "-u", "root", "-e", "bash", "-lc",
      `docker exec ${container} sh -c ${quoted}`],
    { encoding: "utf8" },
  ).split("\0").join("").trim();
}

/**
 * Removes exactly what this probe planted.
 *
 * By recorded PID rather than by name: `exec -a` is a bash builtin that the
 * containers' `sh` does not have, and a pattern loose enough to match a plain
 * `sleep` would be loose enough to kill something else on the machine.
 */
function clearPlanted() {
  try {
    onHost(`[ -f ${PID_FILE} ] || exit 0; while read -r p; do kill "$p" 2>/dev/null; done < ${PID_FILE}; rm -f ${PID_FILE}; sleep 1; ps -e | wc -l`);
  } catch {
    // Nothing planted yet.
  }
}

const sidecar = new Sidecar("D:/LovelyRes/target/debug/lovelyhawk-backend.exe", newDataRoot());

try {
  // Start from a machine nobody has planted on, so the "nothing was cut"
  // case is actually reachable.
  clearPlanted();
  const before = Number(onHost("ps -e | wc -l"));
  console.log(`  ${which}: 起始进程 ${before} 个`);

  const status = await connect(sidecar, labTarget(which));
  if (status.stage !== "connected") throw new Error(JSON.stringify(status));
  const binding = status.bindingHandle;

  // A machine that fits inside the table must not claim to have been cut.
  const small = await sidecar.call(
    "system-info.table.collect",
    { bindingHandle: binding, tab: "processes", maximumRows: 500 },
    120_000,
  );
  console.log(`  未超限时: ${small.rows.length} 行，truncated=${small.truncated}`);
  if (before < 500) {
    check("行数没到上限时不谎报截断", small.truncated, false);
  }

  onHost(`: > ${PID_FILE}; i=0; while [ $i -lt ${PLANTED} ]; do sleep 900 & echo $! >> ${PID_FILE}; i=$((i+1)); done; sleep 2; wc -l < ${PID_FILE}`);
  const after = Number(onHost("ps -e | wc -l"));
  console.log(`  种下之后: ${after} 个进程（表最多显示 500 行）`);
  check("这台机器现在确实超过 500 个进程", after > 500);

  const big = await sidecar.call(
    "system-info.table.collect",
    { bindingHandle: binding, tab: "processes", maximumRows: 500 },
    120_000,
  );
  console.log(`  超限时: ${big.rows.length} 行，truncated=${big.truncated}`);
  check("表满了 500 行", big.rows.length, 500);
  check("并且说清楚还有更多没显示", big.truncated, true);
  // The spare row is only there so the answer can be settled; it must never be
  // shown, or the table would hold one row more than it says it does.
  check("多取的那一行没有混进表里", big.rows.length <= 500);

  // A smaller window is cut sooner, and says so just the same.
  const tiny = await sidecar.call(
    "system-info.table.collect",
    { bindingHandle: binding, tab: "processes", maximumRows: 10 },
    120_000,
  );
  console.log(`  只要 10 行时: ${tiny.rows.length} 行，truncated=${tiny.truncated}`);
  check("小窗口也照样如实说被截断", tiny.truncated, true);
  check("小窗口给的正是要的行数", tiny.rows.length, 10);
} catch (error) {
  console.log(`\nFAILED: ${error.message}`);
  const stderr = sidecar.stderr.join("").trim();
  if (stderr !== "") console.log(stderr.slice(-600));
  failures += 1;
} finally {
  sidecar.close();
  try {
    clearPlanted();
  } catch {
    // The cleanup killing its own shell is not a failure of the check.
  }
}

console.log(`\n${failures === 0 ? "ALL CHECKS PASSED" : `${failures} CHECK(S) FAILED`}`);
process.exitCode = failures === 0 ? 0 : 1;
