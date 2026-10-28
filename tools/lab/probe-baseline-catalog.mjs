// Scans one lab host and prints every baseline check grouped by the software
// it is about, so the answers can be read against the host itself.
//
//   node tools/lab/probe-baseline-catalog.mjs [靶机名] [组件]
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { Sidecar, connect, newDataRoot } from "./rpc-harness.mjs";
import { labTarget } from "./lab-target.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const repository = path.resolve(here, "..", "..");
const backend = path.join(repository, "target", "debug", "lovelyhawk-backend.exe");
const lab = process.argv[2] ?? "arena";
const only = process.argv[3] ?? null;

const dataRoot = newDataRoot();
const sidecar = new Sidecar(backend, dataRoot);
try {
  const status = await connect(sidecar, labTarget(lab));
  if (status.stage !== "connected") throw new Error(JSON.stringify(status));

  const catalog = await sidecar.call("baseline.catalog.get", {});
  const scan = await sidecar.call("baseline.scan", { bindingHandle: status.bindingHandle });
  const byHandle = new Map(catalog.items.map((item) => [item.itemHandle, item]));

  const groups = new Map();
  for (const row of scan.statuses) {
    const item = byHandle.get(row.itemHandle);
    if (item === undefined) continue;
    if (only !== null && item.component !== only) continue;
    if (!groups.has(item.component)) groups.set(item.component, []);
    groups.get(item.component).push({ item, row });
  }

  let applicable = 0;
  let failing = 0;
  let absent = 0;
  console.log(`${lab}：目录 ${catalog.items.length} 项\n`);
  for (const [component, rows] of groups) {
    const missing = rows.filter((entry) => entry.row.observedKind === "not-installed").length;
    console.log(`=== ${component}（${rows.length} 项${missing === rows.length ? "，未安装" : ""}）`);
    for (const { item, row } of rows) {
      if (row.observedKind === "not-installed") { absent += 1; continue; }
      applicable += 1;
      if (!row.compliant) failing += 1;
      const mark = row.compliant ? "  " : "! ";
      console.log(`${mark} ${item.title.padEnd(14)} 读到 ${String(row.observed).padEnd(16)} 建议 ${item.recommendation}${item.writable ? "" : "  [只读]"}`);
    }
    console.log("");
  }
  console.log(`适用 ${applicable} 项，其中不符合 ${failing} 项；不适用 ${absent} 项`);
  await sidecar.call("ssh.binding.disconnect", { bindingHandle: status.bindingHandle });
} catch (error) {
  console.log(`FAILED: ${error.message}`);
  // The sidecar logs why; a failure with only the public message is a failure
  // you cannot act on.
  const noisy = sidecar.stderr.join("").split(/\r?\n/u)
    .filter((line) => /ERROR|WARN/u.test(line));
  for (const line of noisy.slice(-4)) console.log(`  ${line.slice(0, 900)}`);
  process.exitCode = 1;
} finally {
  sidecar.close();
  await new Promise((resolve) => setTimeout(resolve, 400));
  fs.rmSync(dataRoot, { recursive: true, force: true });
}
