// Runs the whole command catalogue against every lab host and prints one table.
//
// A command that fails on one distribution and works on the rest is a porting
// gap; a finding that appears everywhere except one host is a detection gap.
// Both are only visible side by side.
import { execFileSync } from "node:child_process";

import { Sidecar, newDataRoot, connect } from "./rpc-harness.mjs";

const PORTS = {
  ubuntu: 2222, alpine: 2223, debian: 2224, rocky: 2225, alma: 2226,
  openeuler: 2227, anolis: 2228, deepin: 2229, suse: 2230,
};

function wslAddress() {
  const output = execFileSync("wsl.exe", ["-d", "Ubuntu", "-e", "bash", "-lc", "hostname -I"], {
    encoding: "utf8",
  });
  return output.split("\0").join("").trim().split(/\s+/u)[0];
}

function runningHosts() {
  const output = execFileSync(
    "wsl.exe",
    ["-d", "Ubuntu", "-u", "root", "-e", "bash", "-lc",
      "docker ps --filter name=lab- --format '{{.Names}}'"],
    { encoding: "utf8" },
  );
  return output.split("\0").join("").trim().split(/\s+/u)
    .filter((name) => name.startsWith("lab-"))
    .map((name) => name.slice("lab-".length))
    .filter((name) => PORTS[name] !== undefined);
}

const host = wslAddress();
const wanted = process.argv.length > 2 ? process.argv.slice(2) : runningHosts();
const results = new Map();

for (const name of wanted) {
  const sidecar = new Sidecar("D:/LovelyRes/target/debug/lovelyres-backend.exe", newDataRoot());
  try {
    const status = await connect(sidecar, {
      host, port: PORTS[name], username: "root", password: "LabRoot#2026",
    });
    if (status.stage !== "connected") {
      console.log(`${name.padEnd(10)} connect failed`);
      results.set(name, null);
      continue;
    }
    const binding = status.bindingHandle;
    const catalog = await sidecar.call("emergency-command.catalog.load", { bindingHandle: binding });
    const flagged = new Set();
    const failed = new Set();
    for (const command of catalog.commands) {
      try {
        const run = await sidecar.call("emergency-command.run", {
          bindingHandle: binding, snapshotHandle: catalog.snapshotHandle,
          commandHandle: command.commandHandle,
        }, 90_000);
        if (run.resultKind !== "success" && run.resultKind !== "empty") failed.add(command.title);
        if ((run.findingLines?.length ?? 0) > 0) flagged.add(command.title);
      } catch {
        failed.add(command.title);
      }
    }
    results.set(name, { total: catalog.commands.length, flagged, failed });
    console.log(`${name.padEnd(10)} ${catalog.commands.length} commands, ` +
      `${flagged.size} flagged, ${failed.size} failed`);
  } catch (error) {
    console.log(`${name.padEnd(10)} ERROR ${error.message}`);
    results.set(name, null);
  } finally {
    sidecar.close();
  }
}

const live = [...results].filter(([, value]) => value !== null);
if (live.length > 1) {
  const titles = new Set();
  for (const [, value] of live) for (const title of value.flagged) titles.add(title);
  for (const [, value] of live) for (const title of value.failed) titles.add(title);

  console.log(`\n=== per command: + flagged, . quiet, x failed (${live.length} hosts) ===`);
  console.log(`${"".padEnd(34)}${live.map(([name]) => name.slice(0, 4).padEnd(5)).join("")}`);
  const rows = [...titles].map((title) => {
    const cells = live.map(([, value]) =>
      value.failed.has(title) ? "x" : value.flagged.has(title) ? "+" : ".");
    return { title, cells, spread: new Set(cells).size };
  });
  // Anything that behaves the same everywhere is not what this table is for.
  for (const row of rows.filter((entry) => entry.spread > 1)
    .sort((a, b) => b.spread - a.spread || a.title.localeCompare(b.title))) {
    console.log(`${row.title.slice(0, 32).padEnd(34)}${row.cells.map((cell) => cell.padEnd(5)).join("")}`);
  }
}
