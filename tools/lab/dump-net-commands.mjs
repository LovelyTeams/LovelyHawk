// Runs the system-overview commands exactly as the tool sends them, against a
// lab host, and prints the columns the tab would show.
//
//   node tools/lab/dump-net-commands.mjs [靶机名]
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { Sidecar, connect, newDataRoot } from "./rpc-harness.mjs";
import { labTarget } from "./lab-target.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const repository = path.resolve(here, "..", "..");
const backend = path.join(repository, "target", "debug", "lovelyres-backend.exe");
const lab = process.argv[2] ?? "arena";
const TABS = process.argv[3] === undefined
  ? ["network", "open-ports", "established", "services", "autostart", "autoruns"]
  : process.argv[3].split(",");

const dataRoot = newDataRoot();
const sidecar = new Sidecar(backend, dataRoot);
try {
  const status = await connect(sidecar, labTarget(lab));
  if (status.stage !== "connected") throw new Error(JSON.stringify(status));
  console.log(`已连接 ${lab}\n`);

  for (const tab of TABS) {
    const table = await sidecar.call("system-info.table.collect", {
      bindingHandle: status.bindingHandle,
      tab,
      maximumRows: 500,
    });
    console.log(`=== ${tab} — ${table.columns.join(" | ")} ===`);
    console.log(`${table.rows.length} 行${table.truncated ? "（已截断）" : ""}`);
    for (const row of table.rows.slice(0, 40)) {
      const mark = row.risk === "normal" ? "  " : row.risk === "warning" ? "! " : "!!";
      const detail = row.detail ? " [详情]" : "";
      console.log(`${mark} ${row.cells.map((cell) => (cell === "" ? "·" : cell)).join(" | ")}${detail}`);
    }
    console.log("");
  }
  await sidecar.call("ssh.binding.disconnect", { bindingHandle: status.bindingHandle });
} catch (error) {
  console.log(`FAILED: ${error.message}`);
  process.exitCode = 1;
} finally {
  sidecar.close();
  await new Promise((resolve) => setTimeout(resolve, 400));
  fs.rmSync(dataRoot, { recursive: true, force: true });
}
