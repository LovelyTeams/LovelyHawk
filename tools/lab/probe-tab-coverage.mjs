// Collects all twenty-five overview tabs on one machine and reports what each
// one actually returned.
//
// The point is the empty ones. A table can be empty for three reasons the tool
// already tells apart — the tool it needs is not installed, the tool is there
// but did not answer, or the machine really has nothing — and for a fourth it
// does not: the command ran, exited zero, and produced nothing because it was
// written for a different machine. That fourth one renders as "really nothing",
// which on a security table is a false all-clear. It is what
// `find -printf` did on busybox, and this probe exists to find the rest.
//
// Run it on two machines and compare: a tab that is full on one and silently
// empty on the other, with no tool reported missing, is the signature.
//
//   node tools/lab/probe-tab-coverage.mjs
//   LAB=alpine node tools/lab/probe-tab-coverage.mjs
//   LAB=alpine node tools/lab/probe-tab-coverage.mjs --json   # for diffing
import { Sidecar, newDataRoot, connect } from "./rpc-harness.mjs";
import { labTarget } from "./lab-target.mjs";

const which = process.env.LAB ?? "ubuntu";
const asJson = process.argv.includes("--json");

const sidecar = new Sidecar("D:/LovelyRes/target/debug/lovelyhawk-backend.exe", newDataRoot());
const report = {};

try {
  const status = await connect(sidecar, labTarget(which));
  if (status.stage !== "connected") throw new Error(JSON.stringify(status));
  const binding = status.bindingHandle;

  const catalog = await sidecar.call("system-info.catalog.get", {}, 60_000);
  const tabs = (catalog.tabs ?? catalog).map((entry) => entry.key ?? entry);
  if (!asJson) console.log(`  ${which}：${tabs.length} 张表\n`);

  for (const tab of tabs) {
    const outcome = await sidecar.call("system-info.table.collect",
      { bindingHandle: binding, tab, maximumRows: 200 }, 300_000)
      .then((table) => ({
        rows: table.rows.length,
        missingTool: table.missingTool ?? null,
        failedTool: table.failedTool ?? null,
        truncated: table.truncated === true,
      }))
      .catch((error) => ({ rows: -1, error: String(error.message).slice(0, 60) }));
    report[tab] = outcome;
    if (asJson) continue;

    let note = "";
    if (outcome.rows === -1) note = `问不到：${outcome.error}`;
    else if (outcome.missingTool) note = `这台机器没有 ${outcome.missingTool}`;
    else if (outcome.failedTool) note = `${outcome.failedTool} 没答上来`;
    else if (outcome.rows === 0) note = "← 空的，而且没说为什么";
    else if (outcome.truncated) note = "（截断了）";
    console.log(`  ${String(outcome.rows).padStart(4)} 行  ${tab.padEnd(18)} ${note}`);
  }
} catch (error) {
  console.log(`\nFAILED: ${error.message}`);
  const stderr = sidecar.stderr.join("").trim();
  if (stderr !== "") console.log(stderr.slice(-500));
  process.exitCode = 1;
} finally {
  sidecar.close();
}

if (asJson) console.log(JSON.stringify({ target: which, tabs: report }, null, 0));
