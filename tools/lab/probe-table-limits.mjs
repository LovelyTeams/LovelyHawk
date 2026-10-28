// Asks every tab of 主机全景 whether it tells the truth about being cut.
//
// Planting five hundred rows in twenty-five different tabs is not possible, so
// the window is made small instead: ask for three rows. Any tab with four or
// more rows on the machine then has to come back with exactly three and say it
// was cut, and a tab with three or fewer has to say it was not. That exercises
// the same code path a busy host would, on every tab, against a real machine.
//
//   node tools/lab/probe-table-limits.mjs
//   LAB=rocky node tools/lab/probe-table-limits.mjs
import { Sidecar, newDataRoot, connect } from "./rpc-harness.mjs";
import { labTarget } from "./lab-target.mjs";

const which = process.env.LAB ?? "ubuntu";
/** Small enough that almost every tab on a real machine overflows it. */
const WINDOW = 3;
/** What the window itself asks for, so "how many are there really" is known. */
const FULL = 500;

const TABS = [
  "processes", "network", "services", "established", "open-ports", "users",
  "autostart", "cron", "ssh-keys", "login-history", "suid-files", "autoruns",
  "firewall", "env-vars", "shell-configs", "packages", "sudoers", "timers",
  "kernel-modules", "rootcheck", "sensitive", "recent-files", "docker",
  "kubernetes", "web-apps",
];

let failures = 0;
function check(name, actual, expected = true) {
  const ok = actual === expected;
  if (!ok) failures += 1;
  console.log(`  ${ok ? "PASS" : "FAIL"} ${name}${ok ? "" : `\n       expected ${JSON.stringify(expected)}\n       actual   ${JSON.stringify(actual)}`}`);
}

const sidecar = new Sidecar("D:/LovelyRes/target/debug/lovelyhawk-backend.exe", newDataRoot());

try {
  const status = await connect(sidecar, labTarget(which));
  if (status.stage !== "connected") throw new Error(JSON.stringify(status));
  const binding = status.bindingHandle;

  const collect = (tab, maximumRows) => sidecar.call(
    "system-info.table.collect",
    { bindingHandle: binding, tab, maximumRows },
    180_000,
  );

  let exercised = 0;
  for (const tab of TABS) {
    let full;
    let small;
    try {
      full = await collect(tab, FULL);
      small = await collect(tab, WINDOW);
    } catch (error) {
      // A tab this machine cannot answer at all is not this check's business;
      // say so rather than counting it as a pass.
      console.log(`  SKIP ${tab.padEnd(15)} 这台机器答不了：${String(error.message).slice(0, 60)}`);
      continue;
    }
    const total = full.rows.length;
    const overflows = total > WINDOW;
    if (overflows) exercised += 1;
    const verdict = `${tab.padEnd(15)} 共 ${String(total).padStart(3)} 行`
      + ` · 取 ${WINDOW} 行时 ${small.rows.length} 行 truncated=${small.truncated}`;
    console.log(`  ${verdict}`);

    // The window never holds more than it was asked for, whatever the machine
    // returned; the spare row exists only to settle the question.
    check(`${tab}: 不多给行`, small.rows.length <= WINDOW);
    if (overflows) {
      check(`${tab}: 装满了小窗口`, small.rows.length, WINDOW);
      check(`${tab}: 超出时如实说被截断`, small.truncated, true);
    } else {
      check(`${tab}: 没超出时不谎报截断`, small.truncated, false);
      check(`${tab}: 小窗口给全了`, small.rows.length, total);
    }
    // The full window must agree with itself: a tab that fits inside five
    // hundred rows has nothing left over.
    if (total < FULL) check(`${tab}: 取满窗口时不谎报截断`, full.truncated, false);
  }

  console.log(`\n  ${exercised}/${TABS.length} 个标签页在这台机器上真的越过了小窗口`);
  // A run where nothing overflowed proves nothing about truncation.
  check("至少有几个标签页真的走到了超限分支", exercised >= 5);
} catch (error) {
  console.log(`\nFAILED: ${error.message}`);
  const stderr = sidecar.stderr.join("").trim();
  if (stderr !== "") console.log(stderr.slice(-600));
  failures += 1;
} finally {
  sidecar.close();
}

console.log(`\n${failures === 0 ? "ALL CHECKS PASSED" : `${failures} CHECK(S) FAILED`}`);
process.exitCode = failures === 0 ? 0 : 1;
