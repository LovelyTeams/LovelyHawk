// How long the sidecar actually needs, against the bound the client allows.
import { Sidecar, newDataRoot, connect } from "./rpc-harness.mjs";
import { labTarget } from "./lab-target.mjs";

const sidecar = new Sidecar("D:/LovelyRes/target/debug/lovelyres-backend.exe", newDataRoot());
try {
  const status = await connect(sidecar, labTarget());
  const binding = status.bindingHandle;
  const time = async (label, run) => {
    const started = Date.now();
    try {
      await run();
      return { label, ms: Date.now() - started, ok: true };
    } catch (error) {
      return { label, ms: Date.now() - started, ok: false, why: error.message.split(":")[0] };
    }
  };

  const rows = [];
  rows.push(await time("system-info.summary.get", () =>
    sidecar.call("system-info.summary.get", { bindingHandle: binding }, 180_000)));
  for (const tab of ["processes", "suid-files", "recent-files", "sensitive", "packages"]) {
    rows.push(await time(`system-info.table.collect ${tab}`, () =>
      sidecar.call("system-info.table.collect", { bindingHandle: binding, tab, maximumRows: 200 }, 180_000)));
  }
  const catalog = await sidecar.call("emergency-command.catalog.load", { bindingHandle: binding }, 180_000);
  const slowest = catalog.commands.reduce((a, b) => (a.timeoutSeconds > b.timeoutSeconds ? a : b));
  rows.push(await time(`emergency-command.run ${slowest.title}`, () =>
    sidecar.call("emergency-command.run", {
      bindingHandle: binding, snapshotHandle: catalog.snapshotHandle, commandHandle: slowest.commandHandle,
    }, 180_000)));

  for (const row of rows) {
    const verdict = row.ms > 60_000 ? "OVER the 60s remote bound"
      : row.ms > 15_000 ? "would have failed on the old 15s bound" : "";
    console.log(`${String(row.ms).padStart(6)}ms  ${row.ok ? "ok  " : "FAIL"} ${row.label}${verdict ? "  <- " + verdict : ""}`);
  }
} catch (error) {
  console.log("FAILED:", error.message);
} finally {
  sidecar.close();
}
