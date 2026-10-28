// Times how long the command workbench takes to become usable, and checks
// that it says which command set it is offering.
//
// The catalogue runs three probes — which distribution family, which
// containers, which pods — and an operator waits for all of them before the
// page is any use. On a machine under load, which is the machine an operator
// is most likely to be looking at, each one can reach its deadline.
//
//   node tools/lab/probe-catalog-latency.mjs
//   LAB=rocky node tools/lab/probe-catalog-latency.mjs
import { execFileSync } from "node:child_process";

import { Sidecar, newDataRoot, connect } from "./rpc-harness.mjs";
import { labTarget } from "./lab-target.mjs";

const which = process.env.LAB ?? "ubuntu";
const container = `lab-${which}`;

function onHost(command) {
  return execFileSync(
    "wsl.exe",
    ["-d", "Ubuntu", "-u", "root", "-e", "bash", "-lc",
      `docker exec ${container} sh -c ${JSON.stringify(command)}`],
    { encoding: "utf8" },
  ).split("\0").join("").trim();
}

let failures = 0;
function check(name, actual, expected = true) {
  const ok = actual === expected;
  if (!ok) failures += 1;
  console.log(`  ${ok ? "PASS" : "FAIL"} ${name}${ok ? "" : `\n       expected ${JSON.stringify(expected)}\n       actual   ${JSON.stringify(actual)}`}`);
}

const backend = "D:/LovelyRes/target/debug/lovelyhawk-backend.exe";
const sidecar = new Sidecar(backend, newDataRoot());

try {
  const status = await connect(sidecar, labTarget(which));
  if (status.stage !== "connected") throw new Error(JSON.stringify(status));
  const binding = status.bindingHandle;

  const started = Date.now();
  const catalog = await sidecar.call(
    "emergency-command.catalog.load",
    { bindingHandle: binding },
    120_000,
  );
  const elapsed = Date.now() - started;
  console.log(`  ${which}: 目录耗时 ${(elapsed / 1000).toFixed(1)}s，命令 ${catalog.commands.length} 条，`
    + `容器 ${catalog.containers.length} 个，命令集 ${JSON.stringify(catalog.commandSet)}`);

  check("目录里有命令", catalog.commands.length > 0);
  // Three probes that do not depend on each other must not be waited for one
  // after another: the worst case is otherwise three deadlines deep, and the
  // machine that hits it is the busy one an operator cannot afford to wait on.
  check("目录在一个探测期限内返回（三个探测是并发的）", elapsed < 20_000);
  // The page has to be able to say whether it is offering the commands this
  // machine deserves or the portable fallback.
  check("说明了给的是哪一套命令集", ["detected", "portable"].includes(catalog.commandSet));

  // Asking twice is the ordinary case — an operator opens the workbench, goes
  // elsewhere, comes back. The second time must not pay for the probes again.
  const again = Date.now();
  await sidecar.call("emergency-command.catalog.load", { bindingHandle: binding }, 120_000);
  const second = Date.now() - again;
  console.log(`  第二次 ${(second / 1000).toFixed(1)}s`);
  check("这台机器答得出自己是什么系统", catalog.commandSet, "detected");

  // A machine that answers the probe but names a system nobody has heard of
  // gets the portable set just the same. Saying "chosen for your machine"
  // there would be a lie in the one place an operator might act on it, so the
  // word is read from the answer rather than from whether the probe replied.
  onHost("cp /etc/os-release /tmp/os-release.probe.bak"
    + " && printf 'ID=totallyunknownlinux\\n' > /etc/os-release");
  try {
    const fallback = await sidecar.call(
      "emergency-command.catalog.load",
      { bindingHandle: binding },
      120_000,
    );
    console.log(`  认不出的系统 -> ${JSON.stringify(fallback.commandSet)}`);
    check("认不出系统时说清楚给的是通用命令", fallback.commandSet, "portable");
    check("认不出系统也照样给出命令", fallback.commands.length > 0);
  } finally {
    onHost("[ -f /tmp/os-release.probe.bak ] && cp /tmp/os-release.probe.bak /etc/os-release;"
      + " rm -f /tmp/os-release.probe.bak");
  }

  console.log(`\n${failures === 0 ? "ALL CHECKS PASSED" : `${failures} CHECK(S) FAILED`}`);
  process.exitCode = failures === 0 ? 0 : 1;
} catch (error) {
  console.log(`\nFAILED: ${error.message}`);
  const stderr = sidecar.stderr.join("").trim();
  if (stderr !== "") console.log(stderr.slice(-800));
  process.exitCode = 1;
} finally {
  sidecar.close();
}
