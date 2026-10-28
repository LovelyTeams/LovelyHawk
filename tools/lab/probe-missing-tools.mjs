// Asks each tab of 主机全景 to tell the two kinds of empty apart.
//
// An empty firewall table means one of two opposite things: this machine has no
// rules — wide open, act now — or there is no `iptables` here and nobody could
// look. They used to render as the same sentence, and during an incident the
// reassuring reading is the wrong one to hand someone.
//
// The lab machines are containers, so most of these tools genuinely are not
// there; that is what makes them the right place to check.
//
//   node tools/lab/probe-missing-tools.mjs
//   LAB=rocky node tools/lab/probe-missing-tools.mjs
import { execFileSync } from "node:child_process";

import { Sidecar, newDataRoot, connect } from "./rpc-harness.mjs";
import { labTarget } from "./lab-target.mjs";

const which = process.env.LAB ?? "ubuntu";
/**
 * The nine intruded machines are `lab-*`; the orchestration and service hosts
 * are `svc-*`. Both are needed here: the containers that make up the first
 * group have almost none of these tools, which is what makes them good at
 * checking the "missing" side, and useless for checking the other one.
 */
const container = ["docker", "kubernetes", "podman"].includes(which)
  ? `svc-${which}`
  : `lab-${which}`;

/** Tab, the binaries that would answer it, and the name the window may say. */
const NEEDS = [
  { tab: "firewall", binaries: ["iptables-save"], says: "iptables" },
  { tab: "timers", binaries: ["systemctl"], says: "systemctl",
    health: "systemctl list-units --type=timer" },
  { tab: "docker", binaries: ["docker"], says: "docker", health: "docker version" },
  { tab: "kubernetes", binaries: ["kubectl"], says: "kubectl", health: "kubectl version" },
  { tab: "login-history", binaries: ["last"], says: "last" },
  { tab: "web-apps", binaries: ["nginx", "apache2", "httpd"], says: "nginx 或 apache" },
  { tab: "network", binaries: ["ss", "netstat"], says: "ss 或 netstat" },
  { tab: "established", binaries: ["ss", "netstat"], says: "ss 或 netstat" },
  { tab: "open-ports", binaries: ["ss", "netstat"], says: "ss 或 netstat" },
];
/** Reads files or /proc, so an empty table there really is an empty machine. */
const NEEDS_NOTHING = ["processes", "users", "cron", "ssh-keys", "sudoers", "kernel-modules"];

let failures = 0;
function check(name, actual, expected = true) {
  const ok = actual === expected;
  if (!ok) failures += 1;
  console.log(`  ${ok ? "PASS" : "FAIL"} ${name}${ok ? "" : `\n       expected ${JSON.stringify(expected)}\n       actual   ${JSON.stringify(actual)}`}`);
}

function onHost(command) {
  const quoted = `'${command.replace(/'/gu, `'\\''`)}'`;
  return execFileSync(
    "wsl.exe",
    ["-d", "Ubuntu", "-u", "root", "-e", "bash", "-lc",
      `docker exec ${container} sh -c ${quoted}`],
    { encoding: "utf8" },
  ).split("\0").join("").trim();
}

const sidecar = new Sidecar("D:/LovelyRes/target/debug/lovelyhawk-backend.exe", newDataRoot());

try {
  const status = await connect(sidecar, labTarget(which));
  if (status.stage !== "connected") throw new Error(JSON.stringify(status));
  const binding = status.bindingHandle;
  const collect = (tab) => sidecar.call(
    "system-info.table.collect",
    { bindingHandle: binding, tab, maximumRows: 500 },
    180_000,
  );

  let absent = 0;
  for (const { tab, binaries, says, health } of NEEDS) {
    const found = onHost(
      binaries.map((b) => `command -v ${b} >/dev/null 2>&1`).join(" || ") + " && echo yes || echo no",
    ) === "yes";
    const table = await collect(tab);
    if (!found) absent += 1;
    console.log(`  ${tab.padEnd(14)} 机器上${found ? "有" : "没有"} ${binaries.join("/")}`
      + ` · missingTool=${JSON.stringify(table.missingTool)} · ${table.rows.length} 行`);
    if (found) {
      check(`${tab}: 工具在时不推给工具`, table.missingTool, null);
      // Installed is not the same as working: a container has `systemctl` but
      // no systemd to talk to. Rather than letting either answer pass, ask the
      // machine the same question the tab asks and hold the page to it.
      const answers = health === undefined
        ? true
        : onHost(`${health} >/dev/null 2>&1 && echo yes || echo no`) === "yes";
      check(
        `${tab}: 说它答不答得上，要和机器上问出来的一致`,
        table.failedTool,
        answers ? null : says,
      );
    } else {
      check(`${tab}: 工具不在时不说成"答不上来"`, table.failedTool, null);
      check(`${tab}: 工具不在时说清楚是哪一个`, table.missingTool, says);
      // Otherwise the window would show rows it could not have collected.
      check(`${tab}: 工具不在时不编出条目`, table.rows.length, 0);
    }
  }

  // A tab that reads files always has an answer, so it must never blame a tool
  // — including when it legitimately finds nothing.
  for (const tab of NEEDS_NOTHING) {
    const table = await collect(tab);
    check(`${tab}: 读文件的页面从不推给工具`, table.missingTool, null);
  }

  // Installed but not answering is the third kind of empty, and the quietest:
  // nothing about the machine looks wrong. Only worth staging where there is a
  // daemon to stop, so it runs on the docker host and is skipped elsewhere.
  if (which === "docker") {
    const pid = onHost("ps -eo pid=,args= | grep -w dockerd | grep -v grep | awk '{print $1}' | head -1");
    if (pid === "") {
      console.log("  SKIP 守护进程停机场景：这台机器上没有 dockerd 在跑");
    } else {
      onHost(`kill -TERM ${pid} 2>/dev/null; sleep 3; docker version >/dev/null 2>&1 && echo up || echo down`);
      try {
        const dead = await collect("docker");
        console.log(`  守护进程停掉后: missingTool=${JSON.stringify(dead.missingTool)}`
          + ` failedTool=${JSON.stringify(dead.failedTool)} · ${dead.rows.length} 行`);
        check("工具还在，所以不说成没装", dead.missingTool, null);
        check("但说清楚它这次没答上来", dead.failedTool, "docker");
        check("并且不编出条目", dead.rows.length, 0);
      } finally {
        // Restarting the container is what brings the daemon back; killing it
        // left no supervisor to notice.
        execFileSync(
          "wsl.exe",
          ["-d", "Ubuntu", "-u", "root", "-e", "bash", "-lc",
            "docker restart svc-docker >/dev/null 2>&1; sleep 12"],
          { encoding: "utf8" },
        );
        console.log(`  守护进程已恢复：${onHost("docker version >/dev/null 2>&1 && echo answers || echo silent")}`);
      }
    }
  }

  console.log(`\n  这台机器缺 ${absent}/${NEEDS.length} 个工具`);
  check("至少缺一个工具，这轮才算真的验到了", absent >= 1);
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
