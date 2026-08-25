// Nothing collected from a target should come back as a policy marker.
import { Sidecar, newDataRoot, connect } from "./rpc-harness.mjs";
import { labTarget } from "./lab-target.mjs";

const MARKER = /REDACTED|SENSITIVE .* REDACTED/u;
const sidecar = new Sidecar("D:/LovelyRes/target/debug/lovelyres-backend.exe", newDataRoot());
try {
  const status = await connect(sidecar, labTarget());
  const binding = status.bindingHandle;
  const catalog = await sidecar.call("emergency-command.catalog.load", { bindingHandle: binding });

  let scanned = 0;
  const hits = [];
  for (const command of catalog.commands) {
    try {
      const run = await sidecar.call("emergency-command.run", {
        bindingHandle: binding, snapshotHandle: catalog.snapshotHandle, commandHandle: command.commandHandle,
      }, 90_000);
      scanned += 1;
      if (MARKER.test(run.output)) hits.push(`${command.category}/${command.title}`);
    } catch { /* covered by the catalog probe */ }
  }
  console.log(`emergency commands: ${scanned} scanned, ${hits.length} carried a marker`);
  for (const hit of hits) console.log("  !!", hit);

  for (const tab of ["sensitive", "env-vars", "shell-configs", "ssh-keys", "sudoers", "cron"]) {
    const table = await sidecar.call("system-info.table.collect", {
      bindingHandle: binding, tab, maximumRows: 200,
    }, 90_000);
    const text = JSON.stringify(table);
    console.log(`${MARKER.test(text) ? "!!" : "ok"} system-info/${tab} (${table.rows?.length ?? 0} rows)`);
  }

  const sources = await sidecar.call("log-analysis.sources.discover", { bindingHandle: binding });
  const auth = sources.sources.find((s) => s.displayName.includes("auth"));
  const read = await sidecar.call("log-analysis.source.read", {
    bindingHandle: binding, snapshotHandle: sources.snapshotHandle, sourceHandle: auth.sourceHandle,
    input: { page: 1, pageSize: 100, keyword: null, date: null, journalUnit: null },
  }, 90_000);
  console.log(`${MARKER.test(JSON.stringify(read)) ? "!!" : "ok"} log-analysis/auth.log (${read.entryCount} entries)`);
} catch (error) {
  console.log("FAILED:", error.message);
} finally {
  sidecar.close();
}
