// Checks that every lab this repository knows about is in the connection
// store, exactly once, pointing at the address the virtual machine has now.
//
// Adding a family to import-labs.mjs and forgetting to wire it in is silent:
// the import reports success and the window simply does not show the host.
//
//   node tools/lab/verify-import.mjs
import { execFileSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { Sidecar } from "./rpc-harness.mjs";
import {
  ARENA_PORT,
  LAB_PORTS,
  ORCHESTRATION_PORTS,
  SERVICE_PORTS,
} from "./lab-target.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const repository = path.resolve(here, "..", "..");
const archiveRoot = process.env.LOVELYRES_ARCHIVE_ROOT ?? repository;
const backend = path.join(repository, "target", "debug", "lovelyres-backend.exe");

function wslAddress() {
  const output = execFileSync("wsl.exe", ["-d", "Ubuntu", "-e", "bash", "-lc", "hostname -I"], {
    encoding: "utf8",
  });
  return output.split("\0").join("").trim().split(/\s+/u)[0];
}

let failures = 0;
function check(name, actual, expected) {
  const ok = actual === expected;
  if (!ok) failures += 1;
  console.log(`  ${ok ? "PASS" : "FAIL"} ${name}${ok ? "" : `\n       expected ${JSON.stringify(expected)}\n       actual   ${JSON.stringify(actual)}`}`);
}

const expected = [
  ["综合靶机", ARENA_PORT],
  ...Object.values(LAB_PORTS).map((port) => ["被入侵", port]),
  ...Object.values(SERVICE_PORTS).map((port) => ["配置不合规", port]),
  ...Object.values(ORCHESTRATION_PORTS).map((port) => ["容器编排", port]),
];

const address = wslAddress();
const sidecar = new Sidecar(backend, archiveRoot);

try {
  const stored = await sidecar.call("connections.list", {});
  const labs = stored.filter((entry) => (entry.tags ?? []).includes("lab"));
  const ports = labs.map((entry) => entry.port).sort((a, b) => a - b);

  console.log(`连接库里有 ${labs.length} 台实验靶机，期望 ${expected.length} 台\n`);
  for (const entry of labs.slice().sort((a, b) => a.port - b.port)) {
    console.log(`  ${String(entry.port).padEnd(6)} ${entry.name}`);
  }
  console.log();

  check("台数对得上", labs.length, expected.length);
  check(
    "端口一个不少",
    ports.join(","),
    expected.map(([, port]) => port).sort((a, b) => a - b).join(","),
  );
  check("没有重复端口", new Set(ports).size, ports.length);
  check("综合靶机在里面", labs.some((entry) => entry.port === ARENA_PORT), true);
  check(
    "地址都是虚机现在的地址",
    labs.every((entry) => entry.host === address),
    true,
  );

  console.log(`\n${failures === 0 ? "ALL CHECKS PASSED" : `${failures} CHECK(S) FAILED`}`);
  process.exitCode = failures === 0 ? 0 : 1;
} catch (error) {
  console.log(`\nFAILED: ${error.message}`);
  const stderr = sidecar.stderr.join("").trim();
  if (stderr !== "") console.log(stderr.slice(-600));
  process.exitCode = 1;
} finally {
  sidecar.close();
}
