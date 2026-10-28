import { Sidecar, newDataRoot, connect } from "./rpc-harness.mjs";
import { labTarget } from "./lab-target.mjs";

const sidecar = new Sidecar("D:/LovelyRes/target/debug/lovelyhawk-backend.exe", newDataRoot());
try {
  const status = await connect(sidecar, labTarget());
  if (status.stage !== "connected") throw new Error(JSON.stringify(status));
  const binding = status.bindingHandle;

  const summary = await sidecar.call("system-info.summary.get", { bindingHandle: binding }, 120_000);
  const filled = Object.entries(summary).filter(([, value]) => value !== "" && value !== null);
  console.log(`=== system info: ${filled.length}/${Object.keys(summary).length} fields filled ===`);
  for (const [key, value] of filled.slice(0, 14)) console.log(`  ${key.padEnd(22)} ${String(value).slice(0, 60)}`);
  const empty = Object.entries(summary).filter(([, value]) => value === "" || value === null).map(([k]) => k);
  if (empty.length > 0) console.log(`  empty: ${empty.join(", ")}`);

  const catalog = await sidecar.call("system-info.catalog.get", {});
  console.log(`\n=== system info tabs: ${catalog.tabs?.length ?? catalog.length ?? "?"} ===`);
  const tabs = catalog.tabs ?? catalog;
  const names = tabs.map((tab) => tab.key ?? tab);
  console.log(" ", names.join(" "));

  let collected = 0;
  let emptyTabs = [];
  for (const tab of names.slice(0, 30)) {
    try {
      const table = await sidecar.call("system-info.table.collect", {
        bindingHandle: binding, tab, maximumRows: 200,
      }, 90_000);
      collected += 1;
      if ((table.rows?.length ?? 0) === 0) emptyTabs.push(tab);
    } catch (error) {
      emptyTabs.push(`${tab}(${error.message.split(":")[0]})`);
    }
  }
  console.log(`collected ${collected}/${names.length} tabs; no rows: ${emptyTabs.join(" ") || "none"}`);

  const audit = await sidecar.call("check-audit.catalog.get", {
    bindingHandle: binding, input: { customCommandNames: [] },
  }, 90_000);
  console.log(`\n=== check audit: ${audit.commands?.length ?? "?"} commands ===`);
  const state = await sidecar.call("check-audit.status.collect", {
    bindingHandle: binding, snapshotHandle: audit.snapshotHandle,
  }, 120_000);
  console.log(`  sections: ${state.sections?.length ?? 0}, findings: ${state.findings?.length ?? 0}`);
  for (const finding of (state.findings ?? []).slice(0, 8)) {
    console.log(`   [${finding.severity ?? "?"}] ${finding.title ?? JSON.stringify(finding).slice(0, 80)}`);
  }
} catch (error) {
  console.log("FAILED:", error.message);
  console.log(sidecar.stderr.join("").slice(-900));
} finally {
  sidecar.close();
}
